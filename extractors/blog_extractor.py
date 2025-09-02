import requests
from bs4 import BeautifulSoup
import time
import re
from typing import List, Optional, Dict
import sys
import os
import logging
from urllib.parse import urljoin, urlparse
from datetime import datetime

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from data.schema import KnowledgeEntry

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class BlogPostExtractor:
    """Extractor especializado para artículos de seguridad (blogs)"""
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
        })
        
        # Categorías específicas para artículos de seguridad
        self.category_keywords = {
            'tutorial': ['tutorial', 'guide', 'how to', 'step by step', 'walkthrough', 'getting started'],
            'analysis': ['analysis', 'research', 'study', 'investigation', 'deep dive', 'breakdown'],
            'news': ['announcement', 'update', 'release', 'news', 'alert', 'warning'],
            'vulnerability-analysis': ['vulnerability', 'exploit', 'attack', 'bug', 'flaw', 'weakness'],
            'best-practices': ['best practices', 'recommendations', 'guidelines', 'standards', 'patterns'],
            'case-study': ['case study', 'real world', 'incident', 'post-mortem', 'lessons learned'],
            'tool-review': ['tool', 'framework', 'library', 'review', 'comparison', 'benchmark'],
            'reentrancy': ['reentrancy', 'reentrant', 'external call', 'state change'],
            'access-control': ['access control', 'authorization', 'permission', 'owner', 'admin'],
            'integer-overflow': ['overflow', 'underflow', 'arithmetic', 'safe math', 'uint256']
        }
        
        # Patrones para extraer secciones de artículos
        self.blog_patterns = {
            'introduction': r'(?:introduction|intro|overview)\s*:?\s*(.+?)(?=\n\s*(?:main|content|analysis|$))',
            'main_content': r'(?:main\s+content|content|analysis|discussion)\s*:?\s*(.+?)(?=\n\s*(?:conclusion|summary|$))',
            'conclusion': r'(?:conclusion|summary|final\s+thoughts|takeaway)\s*:?\s*(.+?)(?=\n|$)',
            'key_points': r'(?:key\s+points|highlights|important|takeaways)\s*:?\s*(.+?)(?=\n\s*(?:conclusion|$))'
        }
        
        # Sitios conocidos de seguridad
        self.known_security_sites = {
            'openzeppelin.com': 'openzeppelin',
            'consensys.net': 'consensys',
            'trailofbits.com': 'trail-of-bits',
            'paradigm.xyz': 'paradigm',
            'a16zcrypto.com': 'a16z',
            'medium.com': 'medium',
            'mirror.xyz': 'mirror',
            'substack.com': 'substack'
        }
    
    def extract_blog_details(self, blog_url: str) -> Optional[KnowledgeEntry]:
        """Extrae los detalles de un artículo de seguridad"""
        try:
            logger.info(f"Extrayendo artículo desde {blog_url}")
            
            response = self.session.get(blog_url)
            response.raise_for_status()
            
            soup = BeautifulSoup(response.content, 'html.parser')
            
            # Extraer título
            title = self._extract_title(soup, blog_url)
            
            # Extraer contenido estructurado
            content_text = self._extract_structured_content(soup)
            
            # Extraer metadatos
            metadata = self._extract_metadata(soup, content_text, blog_url)
            
            # Categorizar
            category = self._categorize_blog(content_text, metadata)
            
            # Crear tags
            tags = self._create_tags(metadata, category, blog_url)
            
            # Generar ID único
            blog_id = self._generate_blog_id(blog_url, title)
            
            return KnowledgeEntry(
                id=blog_id,
                source_url=blog_url,
                source_type="blog_post",
                title=title,
                content_text=content_text,
                category=category,
                tags=tags,
                severity=metadata.get('severity'),
                cwe_id=metadata.get('cwe_id')
            )
            
        except Exception as e:
            logger.error(f"Error extrayendo artículo {blog_url}: {e}")
            return None
    
    def _extract_title(self, soup: BeautifulSoup, url: str) -> str:
        """Extrae el título del artículo"""
        # Buscar en diferentes ubicaciones
        title_selectors = [
            'h1',
            'h2',
            '.title',
            '.post-title',
            '.article-title',
            '.entry-title',
            'title'
        ]
        
        for selector in title_selectors:
            title_elem = soup.select_one(selector)
            if title_elem:
                title = title_elem.get_text().strip()
                # Filtrar títulos genéricos
                if not any(generic in title.lower() for generic in [
                    'home', 'blog', 'navigation', 'menu', 'sidebar'
                ]):
                    return title
        
        # Fallback: usar el título de la página
        title_tag = soup.find('title')
        if title_tag:
            return title_tag.get_text().strip()
        
        # Último fallback
        parsed_url = urlparse(url)
        return f"Security Article - {parsed_url.netloc}"
    
    def _extract_structured_content(self, soup: BeautifulSoup) -> str:
        """Extrae contenido estructurado del artículo"""
        # Buscar el contenido principal
        main_content = soup.find('main') or soup.find('article') or soup.find('div', class_='content')
        if not main_content:
            # Buscar por selectores comunes
            content_selectors = [
                '.post-content',
                '.article-content',
                '.entry-content',
                '.blog-content',
                '.content'
            ]
            for selector in content_selectors:
                main_content = soup.select_one(selector)
                if main_content:
                    break
        
        if not main_content:
            main_content = soup
        
        # Extraer secciones específicas
        sections = []
        
        # Introducción
        intro = self._find_section(main_content, ['introduction', 'intro', 'overview'])
        if intro:
            sections.append(f"Introduction: {intro}")
        
        # Contenido principal
        main_text = self._extract_main_text(main_content)
        if main_text:
            sections.append(f"Main Content: {main_text}")
        
        # Puntos clave
        key_points = self._find_section(main_content, ['key points', 'highlights', 'important', 'takeaways'])
        if key_points:
            sections.append(f"Key Points: {key_points}")
        
        # Conclusión
        conclusion = self._find_section(main_content, ['conclusion', 'summary', 'final thoughts'])
        if conclusion:
            sections.append(f"Conclusion: {conclusion}")
        
        # Si no encontramos secciones específicas, extraer todo el texto
        if not sections:
            text_content = main_content.get_text()
            # Limpiar el texto
            text_content = re.sub(r'\s+', ' ', text_content)
            text_content = text_content.strip()
            sections.append(text_content)
        
        return ' '.join(sections)
    
    def _extract_main_text(self, content) -> str:
        """Extrae el texto principal del artículo"""
        # Buscar párrafos principales
        paragraphs = content.find_all('p')
        main_text_parts = []
        
        for p in paragraphs:
            p_text = p.get_text().strip()
            # Filtrar párrafos muy cortos o de navegación
            if len(p_text) > 50 and not any(nav in p_text.lower() for nav in [
                'subscribe', 'follow us', 'share this', 'related posts', 'advertisement'
            ]):
                main_text_parts.append(p_text)
        
        return ' '.join(main_text_parts[:10])  # Limitar a los primeros 10 párrafos
    
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
        """Extrae metadatos del artículo"""
        metadata = {
            'author': None,
            'publication_date': None,
            'site_name': None,
            'severity': None,
            'cwe_id': None
        }
        
        # Extraer autor
        author_selectors = [
            '.author',
            '.byline',
            '.post-author',
            '.article-author',
            '[rel="author"]'
        ]
        
        for selector in author_selectors:
            author_elem = soup.select_one(selector)
            if author_elem:
                metadata['author'] = author_elem.get_text().strip()
                break
        
        # Extraer fecha de publicación
        date_selectors = [
            '.date',
            '.published',
            '.post-date',
            '.article-date',
            'time[datetime]'
        ]
        
        for selector in date_selectors:
            date_elem = soup.select_one(selector)
            if date_elem:
                date_text = date_elem.get_text().strip()
                # Intentar extraer fecha
                date_match = re.search(r'(\d{4}[-/]\d{1,2}[-/]\d{1,2})', date_text)
                if date_match:
                    metadata['publication_date'] = date_match.group(1)
                break
        
        # Extraer nombre del sitio
        parsed_url = urlparse(url)
        for site, name in self.known_security_sites.items():
            if site in parsed_url.netloc:
                metadata['site_name'] = name
                break
        
        # Determinar severidad basada en contenido
        content_lower = content_text.lower()
        if any(word in content_lower for word in ['critical', 'severe', 'high risk', 'urgent']):
            metadata['severity'] = 'high'
        elif any(word in content_lower for word in ['medium', 'moderate', 'important']):
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
    
    def _categorize_blog(self, content_text: str, metadata: Dict) -> str:
        """Categoriza el artículo de seguridad"""
        full_text = content_text.lower()
        
        # Buscar la categoría con más coincidencias
        category_scores = {}
        for category, keywords in self.category_keywords.items():
            score = sum(1 for keyword in keywords if keyword in full_text)
            if score > 0:
                category_scores[category] = score
        
        if category_scores:
            return max(category_scores, key=category_scores.get)
        
        return 'security-article'
    
    def _create_tags(self, metadata: Dict, category: str, url: str) -> List[str]:
        """Crea tags para el artículo"""
        tags = ["blog-post", "security-article", category]
        
        if metadata.get('author'):
            tags.append(metadata['author'].lower().replace(' ', '-'))
        
        if metadata.get('site_name'):
            tags.append(metadata['site_name'])
        
        if metadata.get('publication_date'):
            year = metadata['publication_date'][:4]
            tags.append(f"year-{year}")
        
        if metadata.get('severity'):
            tags.append(f"severity-{metadata['severity']}")
        
        if metadata.get('cwe_id'):
            tags.append(metadata['cwe_id'])
        
        # Agregar tags basados en la URL
        parsed_url = urlparse(url)
        if 'openzeppelin' in parsed_url.netloc:
            tags.append('openzeppelin')
        elif 'consensys' in parsed_url.netloc:
            tags.append('consensys')
        elif 'trailofbits' in parsed_url.netloc:
            tags.append('trail-of-bits')
        elif 'medium.com' in parsed_url.netloc:
            tags.append('medium')
        elif 'mirror.xyz' in parsed_url.netloc:
            tags.append('mirror')
        
        return tags
    
    def _generate_blog_id(self, url: str, title: str) -> str:
        """Genera un ID único para el artículo"""
        # Usar el dominio y parte del título
        parsed_url = urlparse(url)
        domain = parsed_url.netloc.replace('www.', '').split('.')[0]
        
        # Crear ID basado en título
        title_slug = re.sub(r'[^a-zA-Z0-9\s]', '', title.lower())
        title_slug = re.sub(r'\s+', '_', title_slug)[:30]
        
        return f"blog_{domain}_{title_slug}"
    
    def extract_blogs_from_list(self, blog_urls: List[str]) -> List[KnowledgeEntry]:
        """Extrae múltiples artículos de seguridad"""
        logger.info(f"Iniciando extracción de {len(blog_urls)} artículos...")
        
        entries = []
        failed_extractions = []
        
        for i, url in enumerate(blog_urls):
            logger.info(f"Procesando artículo {i+1}/{len(blog_urls)}: {url}")
            
            entry = self.extract_blog_details(url)
            if entry:
                entries.append(entry)
                logger.info(f"✅ Artículo extraído exitosamente - {entry.title}")
            else:
                failed_extractions.append(url)
                logger.warning(f"❌ Falló la extracción de {url}")
            
            # Pausa para ser respetuoso con el servidor
            time.sleep(2)
        
        logger.info(f"Extracción de artículos completada: {len(entries)} exitosas, {len(failed_extractions)} fallidas")
        if failed_extractions:
            logger.warning(f"Artículos fallidos: {failed_extractions}")
        
        return entries
