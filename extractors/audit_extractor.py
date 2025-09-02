import requests
from bs4 import BeautifulSoup
import time
import re
from typing import List, Optional, Dict
import sys
import os
import logging
from urllib.parse import urljoin, urlparse

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from data.schema import KnowledgeEntry

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class AuditReportExtractor:
    """Extractor especializado para audit reports de seguridad"""
    
    def __init__(self, target_language: str = "solidity"):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
        })
        
        # Configuración de filtrado por lenguaje
        self.target_language = target_language.lower()
        self.language_keywords = {
            'solidity': ['solidity', 'ethereum', 'evm', 'smart contract', 'erc20', 'erc721', 'erc1155', 'defi', 'web3'],
            'rust': ['rust', 'solana', 'anchor', 'move', 'aptos'],
            'go': ['go', 'golang', 'cosmos', 'tendermint', 'ibc'],
            'javascript': ['javascript', 'node.js', 'typescript', 'web2'],
            'python': ['python', 'django', 'flask', 'fastapi'],
            'java': ['java', 'spring', 'jvm'],
            'c++': ['c++', 'cpp', 'cplusplus'],
            'c#': ['c#', 'csharp', '.net', 'dotnet']
        }
        
        # Categorías específicas para audit reports
        self.category_keywords = {
            'defi-audit': ['defi', 'dex', 'liquidity', 'swap', 'amm', 'yield farming', 'lending', 'borrowing'],
            'nft-audit': ['nft', 'erc721', 'erc1155', 'mint', 'burn', 'metadata', 'royalty'],
            'governance-audit': ['governance', 'voting', 'proposal', 'dao', 'treasury', 'multisig'],
            'bridge-audit': ['bridge', 'cross-chain', 'relay', 'validator', 'consensus'],
            'token-audit': ['token', 'erc20', 'erc777', 'transfer', 'approval', 'allowance'],
            'staking-audit': ['staking', 'validator', 'delegation', 'slashing', 'rewards'],
            'oracle-audit': ['oracle', 'price feed', 'data source', 'aggregator'],
            'access-control': ['access', 'authorization', 'permission', 'owner', 'admin', 'modifier'],
            'reentrancy': ['reentrancy', 'reentrant', 'external call', 'state change'],
            'integer-overflow': ['overflow', 'underflow', 'arithmetic', 'uint256', 'safe math']
        }
        
        # Patrones para extraer secciones de audit reports
        self.audit_patterns = {
            'executive_summary': r'(?:executive\s+summary|summary|overview)\s*:?\s*(.+?)(?=\n\s*(?:findings|recommendations|conclusion|$))',
            'findings': r'(?:findings|vulnerabilities|issues)\s*:?\s*(.+?)(?=\n\s*(?:recommendations|conclusion|$))',
            'recommendations': r'(?:recommendations|suggestions|mitigations)\s*:?\s*(.+?)(?=\n\s*(?:conclusion|appendix|$))',
            'conclusion': r'(?:conclusion|final\s+thoughts|summary)\s*:?\s*(.+?)(?=\n|$)',
            'methodology': r'(?:methodology|approach|scope)\s*:?\s*(.+?)(?=\n\s*(?:findings|executive|$))'
        }
    
    def extract_audit_details(self, audit_url: str) -> Optional[KnowledgeEntry]:
        """Extrae los detalles de un audit report"""
        try:
            logger.info(f"Extrayendo audit report desde {audit_url}")
            
            response = self.session.get(audit_url)
            response.raise_for_status()
            
            soup = BeautifulSoup(response.content, 'html.parser')
            
            # Extraer título
            title = self._extract_title(soup, audit_url)
            
            # Extraer contenido estructurado
            content_text = self._extract_structured_content(soup)
            
            # FILTRAR POR LENGUAJE - Solo continuar si es del lenguaje objetivo
            detected_language = self._detect_language(soup, content_text, audit_url)
            if not self._is_target_language(detected_language):
                logger.info(f"⏭️ Saltando audit {audit_url} - Lenguaje: {detected_language} (objetivo: {self.target_language})")
                return None
            
            # Extraer metadatos
            metadata = self._extract_metadata(soup, content_text, audit_url)
            metadata['detected_language'] = detected_language
            
            # Categorizar
            category = self._categorize_audit(content_text, metadata)
            
            # Crear tags
            tags = self._create_tags(metadata, category, audit_url)
            
            # Generar ID único
            audit_id = self._generate_audit_id(audit_url, title)
            
            logger.info(f"✅ Audit {audit_url} - Lenguaje: {detected_language} - Categoría: {category}")
            
            return KnowledgeEntry(
                id=audit_id,
                source_url=audit_url,
                source_type="audit_report",
                title=title,
                content_text=content_text,
                category=category,
                tags=tags,
                severity=metadata.get('severity'),
                cwe_id=metadata.get('cwe_id')
            )
            
        except Exception as e:
            logger.error(f"Error extrayendo audit report {audit_url}: {e}")
            return None
    
    def _extract_title(self, soup: BeautifulSoup, url: str) -> str:
        """Extrae el título del audit report"""
        # Buscar en diferentes ubicaciones
        title_selectors = [
            'h1',
            'h2',
            '.title',
            '.audit-title',
            '.report-title',
            'title'
        ]
        
        for selector in title_selectors:
            title_elem = soup.select_one(selector)
            if title_elem:
                title = title_elem.get_text().strip()
                # Filtrar títulos genéricos
                if not any(generic in title.lower() for generic in [
                    'audit report', 'security review', 'home', 'navigation'
                ]):
                    return title
        
        # Fallback: usar el dominio y path
        parsed_url = urlparse(url)
        return f"Audit Report - {parsed_url.netloc}"
    
    def _extract_structured_content(self, soup: BeautifulSoup) -> str:
        """Extrae contenido estructurado del audit report"""
        # Buscar el contenido principal
        main_content = soup.find('main') or soup.find('article') or soup.find('div', class_='content')
        if not main_content:
            main_content = soup
        
        # Extraer secciones específicas
        sections = []
        
        # Executive Summary
        exec_summary = self._find_section(main_content, ['executive summary', 'summary', 'overview'])
        if exec_summary:
            sections.append(f"Executive Summary: {exec_summary}")
        
        # Findings
        findings = self._find_section(main_content, ['findings', 'vulnerabilities', 'issues'])
        if findings:
            sections.append(f"Findings: {findings}")
        
        # Recommendations
        recommendations = self._find_section(main_content, ['recommendations', 'suggestions', 'mitigations'])
        if recommendations:
            sections.append(f"Recommendations: {recommendations}")
        
        # Methodology
        methodology = self._find_section(main_content, ['methodology', 'approach', 'scope'])
        if methodology:
            sections.append(f"Methodology: {methodology}")
        
        # Si no encontramos secciones específicas, extraer todo el texto
        if not sections:
            text_content = main_content.get_text()
            # Limpiar el texto
            text_content = re.sub(r'\s+', ' ', text_content)
            text_content = text_content.strip()
            sections.append(text_content)
        
        return ' '.join(sections)
    
    def _find_section(self, content, keywords: List[str]) -> Optional[str]:
        """Busca una sección específica por palabras clave"""
        for elem in content.find_all(['h1', 'h2', 'h3', 'h4', 'h5', 'h6']):
            elem_text = elem.get_text().lower()
            if any(keyword in elem_text for keyword in keywords):
                # Buscar el contenido siguiente
                next_elem = elem.find_next(['p', 'div', 'ul', 'ol'])
                if next_elem:
                    return next_elem.get_text().strip()
        return None
    
    def _extract_metadata(self, soup: BeautifulSoup, content_text: str, url: str) -> Dict[str, Optional[str]]:
        """Extrae metadatos del audit report"""
        metadata = {
            'audit_firm': None,
            'project_name': None,
            'severity': None,
            'cwe_id': None,
            'date': None
        }
        
        # Extraer firma de auditoría
        audit_firms = ['consensys', 'openzeppelin', 'trail of bits', 'quantstamp', 'certik', 'halborn']
        for firm in audit_firms:
            if firm in url.lower() or firm in content_text.lower():
                metadata['audit_firm'] = firm.title()
                break
        
        # Extraer nombre del proyecto
        project_match = re.search(r'(?:audit|review|report)\s+(?:of\s+)?([A-Z][a-zA-Z0-9\s]+)', content_text, re.IGNORECASE)
        if project_match:
            metadata['project_name'] = project_match.group(1).strip()
        
        # Determinar severidad
        content_lower = content_text.lower()
        if any(word in content_lower for word in ['critical', 'severe', 'high risk', 'high severity']):
            metadata['severity'] = 'high'
        elif any(word in content_lower for word in ['medium', 'moderate', 'medium risk']):
            metadata['severity'] = 'medium'
        elif any(word in content_lower for word in ['low', 'minor', 'informational']):
            metadata['severity'] = 'low'
        else:
            metadata['severity'] = 'medium'  # Default
        
        # Buscar CWE IDs
        cwe_match = re.search(r'CWE-(\d+)', content_text)
        if cwe_match:
            metadata['cwe_id'] = f"CWE-{cwe_match.group(1)}"
        
        return metadata
    
    def _categorize_audit(self, content_text: str, metadata: Dict) -> str:
        """Categoriza el audit report"""
        full_text = content_text.lower()
        
        # Buscar la categoría con más coincidencias
        category_scores = {}
        for category, keywords in self.category_keywords.items():
            score = sum(1 for keyword in keywords if keyword in full_text)
            if score > 0:
                category_scores[category] = score
        
        if category_scores:
            return max(category_scores, key=category_scores.get)
        
        return 'audit-report'
    
    def _create_tags(self, metadata: Dict, category: str, url: str) -> List[str]:
        """Crea tags para el audit report"""
        tags = ["audit-report", "security-review", category]
        
        if metadata.get('audit_firm'):
            tags.append(metadata['audit_firm'].lower().replace(' ', '-'))
        
        if metadata.get('project_name'):
            tags.append(metadata['project_name'].lower().replace(' ', '-'))
        
        if metadata.get('severity'):
            tags.append(f"severity-{metadata['severity']}")
        
        if metadata.get('cwe_id'):
            tags.append(metadata['cwe_id'])
        
        # Agregar tags basados en la URL
        parsed_url = urlparse(url)
        if 'consensys' in parsed_url.netloc:
            tags.append('consensys')
        elif 'openzeppelin' in parsed_url.netloc:
            tags.append('openzeppelin')
        elif 'trailofbits' in parsed_url.netloc:
            tags.append('trail-of-bits')
        
        return tags
    
    def _generate_audit_id(self, url: str, title: str) -> str:
        """Genera un ID único para el audit report"""
        # Usar el dominio y parte del título
        parsed_url = urlparse(url)
        domain = parsed_url.netloc.replace('www.', '').split('.')[0]
        
        # Crear ID basado en título
        title_slug = re.sub(r'[^a-zA-Z0-9\s]', '', title.lower())
        title_slug = re.sub(r'\s+', '_', title_slug)[:30]
        
        return f"audit_{domain}_{title_slug}"
    
    def extract_audits_from_list(self, audit_urls: List[str], max_audits: int = 20) -> List[KnowledgeEntry]:
        """Extrae múltiples audit reports"""
        logger.info(f"Iniciando extracción de {len(audit_urls)} audit reports (máximo {max_audits})...")
        
        entries = []
        failed_extractions = []
        
        # Limitar el número de audits a procesar
        urls_to_process = audit_urls[:max_audits]
        
        for i, url in enumerate(urls_to_process):
            logger.info(f"Procesando audit {i+1}/{len(urls_to_process)}: {url}")
            
            entry = self.extract_audit_details(url)
            if entry:
                entries.append(entry)
                logger.info(f"✅ Audit extraído exitosamente - {entry.title}")
            else:
                failed_extractions.append(url)
                logger.warning(f"❌ Falló la extracción de {url}")
            
            # Pausa para ser respetuoso con el servidor (reducido)
            time.sleep(1)
        
        logger.info(f"Extracción de audits completada: {len(entries)} exitosas, {len(failed_extractions)} fallidas")
        if failed_extractions:
            logger.warning(f"Audits fallidos: {failed_extractions}")
        
        return entries
    
    def _detect_language(self, soup: BeautifulSoup, content_text: str, url: str) -> str:
        """Detecta el lenguaje del audit report"""
        # Combinar texto de la página y contenido
        full_text = (soup.get_text() + " " + content_text).lower()
        
        # Buscar etiquetas de lenguaje en la página
        language_tags = soup.find_all(['span', 'div', 'p'], class_=re.compile(r'language|tech|stack'))
        for tag in language_tags:
            tag_text = tag.get_text().lower()
            for lang, keywords in self.language_keywords.items():
                if any(keyword in tag_text for keyword in keywords):
                    return lang
        
        # Buscar en el contenido
        language_scores = {}
        for lang, keywords in self.language_keywords.items():
            score = sum(1 for keyword in keywords if keyword in full_text)
            if score > 0:
                language_scores[lang] = score
        
        if language_scores:
            return max(language_scores, key=language_scores.get)
        
        # Buscar en la URL
        url_lower = url.lower()
        for lang, keywords in self.language_keywords.items():
            if any(keyword in url_lower for keyword in keywords):
                return lang
        
        return 'unknown'
    
    def _is_target_language(self, detected_language: str) -> bool:
        """Verifica si el lenguaje detectado coincide con el objetivo"""
        return detected_language == self.target_language
    
    def discover_audit_urls(self, base_url: str, max_pages: int = 5) -> List[str]:
        """Descubre URLs de audits desde una página principal (ej: hacken.io)"""
        logger.info(f"Descubriendo audit URLs desde {base_url}")
        
        discovered_urls = []
        
        try:
            for page in range(1, max_pages + 1):
                # Construir URL de la página
                if '?' in base_url:
                    page_url = f"{base_url}&page={page}"
                else:
                    page_url = f"{base_url}?page={page}"
                
                logger.info(f"Explorando página {page}: {page_url}")
                
                response = self.session.get(page_url)
                response.raise_for_status()
                
                soup = BeautifulSoup(response.content, 'html.parser')
                
                # Buscar enlaces de audits
                audit_links = self._find_audit_links(soup, base_url)
                discovered_urls.extend(audit_links)
                
                # Si no encontramos más enlaces, parar
                if not audit_links:
                    break
                
                time.sleep(1)  # Pausa entre páginas
            
            logger.info(f"Descubiertas {len(discovered_urls)} URLs de audits")
            return discovered_urls
            
        except Exception as e:
            logger.error(f"Error descubriendo audit URLs: {e}")
            return []
    
    def _find_audit_links(self, soup: BeautifulSoup, base_url: str) -> List[str]:
        """Encuentra enlaces de audits en una página"""
        audit_links = []
        
        # Buscar enlaces que parezcan audits
        for link in soup.find_all('a', href=True):
            href = link['href']
            link_text = link.get_text().lower()
            
            # Convertir a URL absoluta
            if href.startswith('/'):
                full_url = urljoin(base_url, href)
            elif href.startswith('http'):
                full_url = href
            else:
                continue
            
            # FILTRO ESTRICTO: Solo URLs que contengan /audits/ en la ruta
            if '/audits/' in full_url.lower():
                # Verificar que no sea una página de servicios
                if '/services/' not in full_url.lower():
                    # Verificar que sea una URL específica de audit (no página general)
                    if full_url.lower() != base_url.lower() and full_url.lower() != base_url.lower() + '/':
                        # Verificar que tenga un formato de audit específico
                        if any(pattern in full_url.lower() for pattern in ['/audits/202', '/audits/201', '/audits/']):
                            audit_links.append(full_url)
        
        return list(set(audit_links))  # Eliminar duplicados
