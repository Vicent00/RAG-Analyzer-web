import re
import tiktoken
from typing import List, Dict, Any
from dataclasses import dataclass
import logging

logger = logging.getLogger(__name__)

@dataclass
class Chunk:
    """Representa un chunk de texto con metadatos"""
    id: str
    content: str
    chunk_type: str  # 'title', 'description', 'remediation', 'code', 'references'
    source_id: str
    source_url: str
    category: str
    severity: str
    cwe_id: str
    chunk_index: int
    total_chunks: int
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "content": self.content,
            "chunk_type": self.chunk_type,
            "source_id": self.source_id,
            "source_url": self.source_url,
            "category": self.category,
            "severity": self.severity,
            "cwe_id": self.cwe_id,
            "chunk_index": self.chunk_index,
            "total_chunks": self.total_chunks
        }

class IntelligentChunker:
    """Chunker inteligente basado en secciones estructuradas"""
    
    def __init__(self, model_name: str = "gpt-3.5-turbo"):
        # Configuración de tokens
        self.encoding = tiktoken.encoding_for_model(model_name)
        self.max_tokens = 500  # Tamaño máximo por chunk
        self.overlap_tokens = 50  # Solapamiento entre chunks
        
        # Patrones para identificar secciones (ajustados al formato real)
        self.section_patterns = {
            'description': r'Description:\s*(.+?)(?=\n\s*(?:Relationships|Remediation|References|Vulnerable Code|Fixed Code|$))',
            'relationships': r'Relationships:\s*(.+?)(?=\n\s*(?:Description|Remediation|References|Vulnerable Code|Fixed Code|$))',
            'remediation': r'Remediation:\s*(.+?)(?=\n\s*(?:References|Vulnerable Code|Fixed Code|$))',
            'references': r'References:\s*(.+?)(?=\n\s*(?:Vulnerable Code|Fixed Code|$))',
            'vulnerable_code': r'Vulnerable Code Example:\s*(.+?)(?=\n\s*(?:Fixed Code|$))',
            'fixed_code': r'Fixed Code Example:\s*(.+?)(?=\n|$)'
        }
    
    def count_tokens(self, text: str) -> int:
        """Cuenta el número de tokens en un texto"""
        return len(self.encoding.encode(text))
    
    def split_text_by_tokens(self, text: str, max_tokens: int, overlap_tokens: int = 0) -> List[str]:
        """Divide un texto en chunks basado en tokens con solapamiento"""
        if self.count_tokens(text) <= max_tokens:
            return [text]
        
        chunks = []
        tokens = self.encoding.encode(text)
        
        start = 0
        while start < len(tokens):
            end = start + max_tokens
            chunk_tokens = tokens[start:end]
            chunk_text = self.encoding.decode(chunk_tokens)
            
            # Intentar cortar en un punto lógico (punto, salto de línea, etc.)
            if end < len(tokens):
                # Buscar el último punto o salto de línea
                for i in range(len(chunk_text) - 1, -1, -1):
                    if chunk_text[i] in '.!?\n':
                        chunk_text = chunk_text[:i + 1]
                        break
            
            chunks.append(chunk_text.strip())
            
            # Calcular el siguiente start con solapamiento
            if end >= len(tokens):
                break
            start = end - overlap_tokens
        
        return chunks
    
    def extract_sections(self, content: str) -> Dict[str, str]:
        """Extrae secciones estructuradas del contenido"""
        sections = {}
        
        for section_name, pattern in self.section_patterns.items():
            match = re.search(pattern, content, re.DOTALL | re.IGNORECASE)
            if match:
                sections[section_name] = match.group(1).strip()
        
        return sections
    
    def create_chunks_from_sections(self, entry_data: Dict[str, Any]) -> List[Chunk]:
        """Crea chunks inteligentes basados en secciones estructuradas"""
        chunks = []
        source_id = entry_data['id']
        source_url = entry_data['source_url']
        category = entry_data['category']
        severity = entry_data['severity']
        cwe_id = entry_data['cwe_id']
        
        # Extraer secciones del contenido
        sections = self.extract_sections(entry_data['content_text'])
        
        chunk_index = 0
        
        # 1. Chunk del título (usar el título de la entrada)
        title = entry_data.get('title', f'SWC-{source_id.split("_")[-1]}')
        title_chunk = Chunk(
            id=f"{source_id}_title",
            content=f"Vulnerability: {title}",
            chunk_type="title",
            source_id=source_id,
            source_url=source_url,
            category=category,
            severity=severity,
            cwe_id=cwe_id,
            chunk_index=chunk_index,
            total_chunks=0  # Se actualizará al final
        )
        chunks.append(title_chunk)
        chunk_index += 1
        
        # 2. Chunk de descripción
        if 'description' in sections:
            desc_content = f"Description: {sections['description']}"
            if self.count_tokens(desc_content) > self.max_tokens:
                # Dividir descripción en chunks más pequeños
                desc_chunks = self.split_text_by_tokens(desc_content, self.max_tokens, self.overlap_tokens)
                for i, desc_chunk in enumerate(desc_chunks):
                    chunk = Chunk(
                        id=f"{source_id}_description_{i}",
                        content=desc_chunk,
                        chunk_type="description",
                        source_id=source_id,
                        source_url=source_url,
                        category=category,
                        severity=severity,
                        cwe_id=cwe_id,
                        chunk_index=chunk_index,
                        total_chunks=0
                    )
                    chunks.append(chunk)
                    chunk_index += 1
            else:
                chunk = Chunk(
                    id=f"{source_id}_description",
                    content=desc_content,
                    chunk_type="description",
                    source_id=source_id,
                    source_url=source_url,
                    category=category,
                    severity=severity,
                    cwe_id=cwe_id,
                    chunk_index=chunk_index,
                    total_chunks=0
                )
                chunks.append(chunk)
                chunk_index += 1
        
        # 3. Chunk de relaciones (CWE, etc.)
        if 'relationships' in sections:
            rel_content = f"Relationships: {sections['relationships']}"
            chunk = Chunk(
                id=f"{source_id}_relationships",
                content=rel_content,
                chunk_type="relationships",
                source_id=source_id,
                source_url=source_url,
                category=category,
                severity=severity,
                cwe_id=cwe_id,
                chunk_index=chunk_index,
                total_chunks=0
            )
            chunks.append(chunk)
            chunk_index += 1
        
        # 4. Chunk de remediación
        if 'remediation' in sections:
            rem_content = f"Remediation: {sections['remediation']}"
            if self.count_tokens(rem_content) > self.max_tokens:
                rem_chunks = self.split_text_by_tokens(rem_content, self.max_tokens, self.overlap_tokens)
                for i, rem_chunk in enumerate(rem_chunks):
                    chunk = Chunk(
                        id=f"{source_id}_remediation_{i}",
                        content=rem_chunk,
                        chunk_type="remediation",
                        source_id=source_id,
                        source_url=source_url,
                        category=category,
                        severity=severity,
                        cwe_id=cwe_id,
                        chunk_index=chunk_index,
                        total_chunks=0
                    )
                    chunks.append(chunk)
                    chunk_index += 1
            else:
                chunk = Chunk(
                    id=f"{source_id}_remediation",
                    content=rem_content,
                    chunk_type="remediation",
                    source_id=source_id,
                    source_url=source_url,
                    category=category,
                    severity=severity,
                    cwe_id=cwe_id,
                    chunk_index=chunk_index,
                    total_chunks=0
                )
                chunks.append(chunk)
                chunk_index += 1
        
        # 5. Chunk de código vulnerable
        if 'vulnerable_code' in sections:
            vuln_content = f"Vulnerable Code Example: {sections['vulnerable_code']}"
            chunk = Chunk(
                id=f"{source_id}_vulnerable_code",
                content=vuln_content,
                chunk_type="vulnerable_code",
                source_id=source_id,
                source_url=source_url,
                category=category,
                severity=severity,
                cwe_id=cwe_id,
                chunk_index=chunk_index,
                total_chunks=0
            )
            chunks.append(chunk)
            chunk_index += 1
        
        # 6. Chunk de código corregido
        if 'fixed_code' in sections:
            fixed_content = f"Fixed Code Example: {sections['fixed_code']}"
            chunk = Chunk(
                id=f"{source_id}_fixed_code",
                content=fixed_content,
                chunk_type="fixed_code",
                source_id=source_id,
                source_url=source_url,
                category=category,
                severity=severity,
                cwe_id=cwe_id,
                chunk_index=chunk_index,
                total_chunks=0
            )
            chunks.append(chunk)
            chunk_index += 1
        
        # 7. Chunk de referencias
        if 'references' in sections:
            ref_content = f"References: {sections['references']}"
            chunk = Chunk(
                id=f"{source_id}_references",
                content=ref_content,
                chunk_type="references",
                source_id=source_id,
                source_url=source_url,
                category=category,
                severity=severity,
                cwe_id=cwe_id,
                chunk_index=chunk_index,
                total_chunks=0
            )
            chunks.append(chunk)
            chunk_index += 1
        
        # Actualizar total_chunks en todos los chunks
        for chunk in chunks:
            chunk.total_chunks = len(chunks)
        
        return chunks
    
    def chunk_knowledge_base(self, knowledge_base_file: str) -> List[Chunk]:
        """Procesa toda la base de conocimiento y crea chunks inteligentes"""
        import json
        
        logger.info(f"Iniciando chunking inteligente de {knowledge_base_file}")
        
        all_chunks = []
        
        with open(knowledge_base_file, 'r', encoding='utf-8') as f:
            for line_num, line in enumerate(f, 1):
                try:
                    entry_data = json.loads(line.strip())
                    chunks = self.create_chunks_from_sections(entry_data)
                    all_chunks.extend(chunks)
                    
                    logger.info(f"Procesada entrada {entry_data['id']}: {len(chunks)} chunks creados")
                    
                except json.JSONDecodeError as e:
                    logger.error(f"Error parseando línea {line_num}: {e}")
                    continue
        
        logger.info(f"Chunking completado: {len(all_chunks)} chunks totales creados")
        return all_chunks
    
    def save_chunks(self, chunks: List[Chunk], output_file: str):
        """Guarda los chunks en formato JSONL"""
        import json
        
        with open(output_file, 'w', encoding='utf-8') as f:
            for chunk in chunks:
                f.write(json.dumps(chunk.to_dict(), ensure_ascii=False) + '\n')
        
        logger.info(f"Guardados {len(chunks)} chunks en {output_file}")
    
    def get_chunk_statistics(self, chunks: List[Chunk]) -> Dict[str, Any]:
        """Obtiene estadísticas de los chunks"""
        stats = {
            'total_chunks': len(chunks),
            'chunks_by_type': {},
            'chunks_by_category': {},
            'chunks_by_severity': {},
            'avg_tokens_per_chunk': 0,
            'total_tokens': 0
        }
        
        total_tokens = 0
        
        for chunk in chunks:
            # Por tipo
            chunk_type = chunk.chunk_type
            stats['chunks_by_type'][chunk_type] = stats['chunks_by_type'].get(chunk_type, 0) + 1
            
            # Por categoría
            category = chunk.category
            stats['chunks_by_category'][category] = stats['chunks_by_category'].get(category, 0) + 1
            
            # Por severidad
            severity = chunk.severity
            stats['chunks_by_severity'][severity] = stats['chunks_by_severity'].get(severity, 0) + 1
            
            # Tokens
            tokens = self.count_tokens(chunk.content)
            total_tokens += tokens
        
        stats['total_tokens'] = total_tokens
        stats['avg_tokens_per_chunk'] = total_tokens / len(chunks) if chunks else 0
        
        return stats
