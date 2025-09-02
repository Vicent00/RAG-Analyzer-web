import requests
from bs4 import BeautifulSoup
import time
import re
from typing import List, Optional, Dict, Tuple
import sys
import os
import logging

# Añadir el directorio padre al path para importar el schema
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from data.schema import KnowledgeEntry

# Configurar logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class ImprovedSWCExtractor:
    """Extractor profesional mejorado para el SWC Registry con chunking inteligente"""
    
    def __init__(self):
        self.base_url = "https://swcregistry.io"
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
        })
        
        # Mapeo de categorías mejorado
        self.category_keywords = {
            'reentrancy': ['reentrancy', 'reentrant', 'call.value', 'external call', 'state change'],
            'integer-overflow': ['overflow', 'underflow', 'integer', 'arithmetic', 'uint256', 'int256'],
            'access-control': ['access', 'authorization', 'permission', 'owner', 'admin', 'modifier'],
            'unchecked-calls': ['call', 'delegatecall', 'send', 'transfer', 'unchecked'],
            'denial-of-service': ['dos', 'denial of service', 'gas limit', 'infinite loop', 'gas'],
            'front-running': ['front run', 'transaction order', 'race condition', 'mev'],
            'timestamp-dependence': ['timestamp', 'block.timestamp', 'now', 'time'],
            'randomness': ['random', 'blockhash', 'block.number', 'pseudorandom'],
            'signature-malleability': ['signature', 'ecrecover', 'malleability', 'v', 'r', 's'],
            'tx-origin': ['tx.origin', 'origin', 'msg.sender'],
            'uninitialized-storage': ['uninitialized', 'storage', 'variable'],
            'uninitialized-memory': ['memory', 'uninitialized', 'local variable']
        }
        
        # Patrones para extraer secciones específicas
        self.section_patterns = {
            'title': r'Title\s*:\s*(.+?)(?=\n|$)',
            'description': r'Description\s*:\s*(.+?)(?=\n\s*(?:Remediation|References|Samples|Relationships|$))',
            'remediation': r'Remediation\s*:\s*(.+?)(?=\n\s*(?:References|Samples|Relationships|$))',
            'relationships': r'Relationships\s*:\s*(.+?)(?=\n\s*(?:Description|Remediation|References|Samples|$))',
            'references': r'References\s*:\s*(.+?)(?=\n\s*(?:Samples|Relationships|$))'
        }
    
    def get_swc_list(self) -> List[str]:
        """Obtiene la lista de todos los SWC IDs"""
        try:
            response = self.session.get(f"{self.base_url}/")
            response.raise_for_status()
            
            soup = BeautifulSoup(response.content, 'html.parser')
            swc_links = []
            
            # Buscar enlaces que contengan SWC-XXX
            for link in soup.find_all('a', href=True):
                href = link['href']
                if 'SWC-' in href and href.endswith('/'):
                    swc_id = href.rstrip('/').split('/')[-1]
                    if swc_id.startswith('SWC-'):
                        swc_links.append(swc_id)
            
            return sorted(list(set(swc_links)))
            
        except Exception as e:
            logger.error(f"Error obteniendo lista de SWCs: {e}")
            return []
    
    def _extract_clean_title(self, soup: BeautifulSoup, swc_id: str) -> str:
        """Extrae el título real del SWC, limpiando contenido innecesario"""
        # Buscar en diferentes ubicaciones
        title_selectors = [
            'h1',
            'h2', 
            '.md-content h1',
            '.md-content h2',
            'title'
        ]
        
        for selector in title_selectors:
            title_elem = soup.select_one(selector)
            if title_elem:
                title = title_elem.get_text().strip()
                # Filtrar títulos genéricos y contenido de navegación
                if not any(generic in title.lower() for generic in [
                    'please note', 'swc registry', 'overview', 'smart contract weakness',
                    'relationships', 'description', 'remediation', 'references'
                ]):
                    # Limpiar el título
                    title = re.sub(r'^SWC-\d+\s*', '', title)  # Remover SWC-XXX del inicio
                    title = re.sub(r'\s+', ' ', title)  # Normalizar espacios
                    if title and len(title) > 3:  # Asegurar que no esté vacío
                        return title
        
        # Si no encontramos un título válido, usar un título genérico basado en el SWC
        swc_titles = {
            'SWC-100': 'Unchecked Call Return Value',
            'SWC-101': 'Integer Overflow and Underflow',
            'SWC-102': 'Outdated Compiler Version',
            'SWC-103': 'Floating Pragma',
            'SWC-104': 'Unchecked Call Return Value',
            'SWC-105': 'Unchecked Call Return Value',
            'SWC-106': 'Unchecked Call Return Value',
            'SWC-107': 'Reentrancy',
            'SWC-108': 'State Variable Default Visibility',
            'SWC-109': 'Uninitialized Storage Pointer',
            'SWC-110': 'Assert Violation',
            'SWC-111': 'Use of Deprecated Solidity Functions',
            'SWC-112': 'Delegatecall to Untrusted Callee',
            'SWC-113': 'DoS with Failed Call',
            'SWC-114': 'Transaction Order Dependence',
            'SWC-115': 'Authorization through tx.origin',
            'SWC-116': 'Timestamp Dependence',
            'SWC-117': 'Signature Malleability',
            'SWC-118': 'Incorrect Constructor Name',
            'SWC-119': 'Shadowing State Variables',
            'SWC-120': 'Weak Sources of Randomness from Chain Attributes',
            'SWC-121': 'Missing Protection against Signature Replay Attacks',
            'SWC-122': 'Lack of Proper Signature Verification',
            'SWC-123': 'Requirement Violation',
            'SWC-124': 'Write to Arbitrary Storage Location',
            'SWC-125': 'Incorrect Inheritance Order',
            'SWC-126': 'Insufficient Gas Griefing',
            'SWC-127': 'Arbitrary Jump with Function Type Variable',
            'SWC-128': 'DoS With Block Gas Limit',
            'SWC-129': 'Typographical Error',
            'SWC-130': 'Right-to-Left Override Character',
            'SWC-131': 'Presence of Unused Variables',
            'SWC-132': 'Unexpected Ether Balance',
            'SWC-133': 'Hash Collisions With Multiple Variable Length Arguments',
            'SWC-134': 'Message call with hardcoded gas amount',
            'SWC-135': 'Code With No Effects',
            'SWC-136': 'Unencrypted Private Data On-Chain'
        }
        
        return swc_titles.get(swc_id, f"SWC-{swc_id}")
    
    def _extract_structured_sections(self, soup: BeautifulSoup) -> Dict[str, str]:
        """Extrae secciones estructuradas del contenido"""
        sections = {}
        
        # Buscar el contenido principal
        main_content = soup.find('main') or soup.find('article') or soup.find('div', class_='md-content')
        if not main_content:
            return sections
        
        # Extraer título
        title_elem = main_content.find('h1') or main_content.find('h2')
        if title_elem:
            title_text = title_elem.get_text().strip()
            if not any(generic in title_text.lower() for generic in ['please note', 'overview']):
                sections['title'] = title_text
        
        # Extraer descripción (primer párrafo significativo)
        for p in main_content.find_all('p'):
            p_text = p.get_text().strip()
            if len(p_text) > 50 and not any(generic in p_text.lower() for generic in [
                'please note', 'swc registry', 'overview', 'swc-100', 'swc-101'
            ]):
                sections['description'] = p_text
                break
        
        # Extraer remediación
        for elem in main_content.find_all(['h1', 'h2', 'h3', 'h4']):
            if 'remediation' in elem.get_text().lower():
                # Buscar el siguiente párrafo o lista
                next_elem = elem.find_next(['p', 'ul', 'ol'])
                if next_elem:
                    sections['remediation'] = next_elem.get_text().strip()
                break
        
        # Extraer relaciones (CWE, etc.)
        for elem in main_content.find_all(['h1', 'h2', 'h3', 'h4']):
            if 'relationship' in elem.get_text().lower():
                next_elem = elem.find_next(['p', 'ul', 'ol'])
                if next_elem:
                    sections['relationships'] = next_elem.get_text().strip()
                break
        
        # Extraer referencias
        for elem in main_content.find_all(['h1', 'h2', 'h3', 'h4']):
            if 'reference' in elem.get_text().lower():
                ref_elem = elem.find_next(['ul', 'ol', 'p'])
                if ref_elem:
                    sections['references'] = ref_elem.get_text().strip()
                break
        
        return sections
    
    def _extract_code_samples(self, soup: BeautifulSoup) -> List[Dict[str, str]]:
        """Extrae muestras de código (vulnerable y corregido)"""
        code_samples = []
        
        # Buscar bloques de código
        code_blocks = soup.find_all('pre') or soup.find_all('code')
        
        for block in code_blocks:
            code_text = block.get_text().strip()
            if len(code_text) > 50 and 'pragma solidity' in code_text:
                # Determinar si es código vulnerable o corregido
                is_fixed = any(keyword in code_text.lower() for keyword in [
                    'fixed', 'safe', 'corrected', 'secure'
                ])
                
                code_samples.append({
                    'type': 'fixed' if is_fixed else 'vulnerable',
                    'code': code_text
                })
        
        return code_samples
    
    def _extract_metadata(self, content_text: str, sections: Dict[str, str]) -> Dict[str, Optional[str]]:
        """Extrae metadatos mejorados"""
        metadata = {'cwe_id': None, 'severity': None}
        
        # Buscar CWE ID en todo el contenido
        full_text = content_text + ' ' + ' '.join(sections.values())
        cwe_match = re.search(r'CWE-(\d+)', full_text)
        if cwe_match:
            metadata['cwe_id'] = f"CWE-{cwe_match.group(1)}"
        
        # Determinar severidad basada en contenido
        content_lower = full_text.lower()
        if any(word in content_lower for word in ['critical', 'severe', 'high', 'dangerous']):
            metadata['severity'] = 'high'
        elif any(word in content_lower for word in ['medium', 'moderate', 'important']):
            metadata['severity'] = 'medium'
        elif any(word in content_lower for word in ['low', 'minor', 'informational']):
            metadata['severity'] = 'low'
        else:
            metadata['severity'] = 'medium'  # Default
        
        return metadata
    
    def _categorize_vulnerability(self, content_text: str, sections: Dict[str, str]) -> str:
        """Categoriza la vulnerabilidad con mayor precisión"""
        full_text = content_text + ' ' + ' '.join(sections.values())
        content_lower = full_text.lower()
        
        # Buscar la categoría con más coincidencias
        category_scores = {}
        for category, keywords in self.category_keywords.items():
            score = sum(1 for keyword in keywords if keyword in content_lower)
            if score > 0:
                category_scores[category] = score
        
        if category_scores:
            return max(category_scores, key=category_scores.get)
        
        return 'vulnerability'
    
    def _create_structured_content(self, sections: Dict[str, str], code_samples: List[Dict[str, str]]) -> str:
        """Crea contenido estructurado para mejor chunking"""
        structured_parts = []
        
        # Título
        if 'title' in sections:
            structured_parts.append(f"Vulnerability: {sections['title']}")
        
        # Descripción
        if 'description' in sections:
            structured_parts.append(f"Description: {sections['description']}")
        
        # Relaciones (CWE, etc.)
        if 'relationships' in sections:
            structured_parts.append(f"Relationships: {sections['relationships']}")
        
        # Remediation
        if 'remediation' in sections:
            structured_parts.append(f"Remediation: {sections['remediation']}")
        
        # Referencias
        if 'references' in sections:
            structured_parts.append(f"References: {sections['references']}")
        
        # Código vulnerable
        vulnerable_code = [sample['code'] for sample in code_samples if sample['type'] == 'vulnerable']
        if vulnerable_code:
            structured_parts.append(f"Vulnerable Code Example: {vulnerable_code[0][:500]}...")
        
        # Código corregido
        fixed_code = [sample['code'] for sample in code_samples if sample['type'] == 'fixed']
        if fixed_code:
            structured_parts.append(f"Fixed Code Example: {fixed_code[0][:500]}...")
        
        return ' '.join(structured_parts)
    
    def extract_swc_details(self, swc_id: str) -> Optional[KnowledgeEntry]:
        """Extrae los detalles de un SWC con estructura mejorada"""
        try:
            url = f"{self.base_url}/docs/{swc_id}/"
            logger.info(f"Extrayendo SWC {swc_id} desde {url}")
            
            response = self.session.get(url)
            response.raise_for_status()
            
            soup = BeautifulSoup(response.content, 'html.parser')
            
            # Extraer título limpio
            title = self._extract_clean_title(soup, swc_id)
            
            # Extraer secciones estructuradas
            sections = self._extract_structured_sections(soup)
            
            # Extraer muestras de código
            code_samples = self._extract_code_samples(soup)
            
            # Crear contenido estructurado
            content_text = self._create_structured_content(sections, code_samples)
            
            # Extraer metadatos
            metadata = self._extract_metadata(content_text, sections)
            
            # Categorizar vulnerabilidad
            category = self._categorize_vulnerability(content_text, sections)
            
            # Crear tags mejorados
            tags = [swc_id, "smart-contract", "vulnerability", category]
            if metadata['cwe_id']:
                tags.append(metadata['cwe_id'])
            if metadata['severity']:
                tags.append(f"severity-{metadata['severity']}")
            
            return KnowledgeEntry(
                id=f"swc_{swc_id}",
                source_url=url,
                source_type="swc_registry",
                title=title,
                content_text=content_text,
                category=category,
                tags=tags,
                severity=metadata['severity'],
                cwe_id=metadata['cwe_id']
            )
            
        except Exception as e:
            logger.error(f"Error extrayendo SWC {swc_id}: {e}")
            return None
    
    def extract_all_swcs(self, max_swcs: int = 10) -> List[KnowledgeEntry]:
        """Extrae todos los SWCs con logging profesional"""
        logger.info("Iniciando extracción mejorada de SWCs...")
        swc_list = self.get_swc_list()
        
        if not swc_list:
            logger.warning("No se encontraron SWCs")
            return []
        
        logger.info(f"Encontrados {len(swc_list)} SWCs. Extrayendo los primeros {max_swcs}...")
        
        entries = []
        failed_extractions = []
        
        for i, swc_id in enumerate(swc_list[:max_swcs]):
            logger.info(f"Procesando {swc_id} ({i+1}/{max_swcs})...")
            
            entry = self.extract_swc_details(swc_id)
            if entry:
                entries.append(entry)
                logger.info(f"✅ {swc_id} extraído exitosamente - Categoría: {entry.category}, Severidad: {entry.severity}")
            else:
                failed_extractions.append(swc_id)
                logger.warning(f"❌ Falló la extracción de {swc_id}")
            
            # Pausa para ser respetuoso con el servidor
            time.sleep(1)
        
        logger.info(f"Extracción completada: {len(entries)} exitosas, {len(failed_extractions)} fallidas")
        if failed_extractions:
            logger.warning(f"SWCs fallidos: {failed_extractions}")
        
        return entries
