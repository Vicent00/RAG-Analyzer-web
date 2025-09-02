import os
import logging
from datetime import datetime
from extractors.swc_extractor import ImprovedSWCExtractor
from extractors.audit_extractor import AuditReportExtractor
from extractors.blog_extractor import BlogPostExtractor
from data.schema import KnowledgeEntry
from chunking.intelligent_chunker import IntelligentChunker

def setup_logging():
    """Configura el sistema de logging"""
    # Crear directorio de logs si no existe
    if not os.path.exists('logs'):
        os.makedirs('logs')
    
    # Configurar logging con archivo
    log_filename = f"logs/extraction_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_filename, encoding='utf-8'),
            logging.StreamHandler()  # También mostrar en consola
        ]
    )
    return log_filename

def create_data_directory():
    """Crea el directorio de datos si no existe"""
    if not os.path.exists('data'):
        os.makedirs('data')
        print("📁 Directorio 'data' creado")

def save_knowledge_base(entries: list, filename: str = "data/knowledge_base.jsonl"):
    """Guarda las entradas en formato JSONL"""
    # Obtener la ruta absoluta del archivo
    abs_path = os.path.abspath(filename)
    
    with open(filename, 'w', encoding='utf-8') as f:
        for entry in entries:
            f.write(entry.to_jsonl() + '\n')
    
    print(f"💾 Guardadas {len(entries)} entradas en:")
    print(f"   📄 Archivo: {filename}")
    print(f"   📍 Ruta completa: {abs_path}")
    
    return abs_path

def main():
    """Función principal para extraer datos del SWC Registry"""
    print("=" * 60)
    print("🚀 SWC REGISTRY EXTRACTOR - SISTEMA RAG")
    print("=" * 60)
    
    # Configurar logging
    log_file = setup_logging()
    print(f"📝 Log guardado en: {os.path.abspath(log_file)}")
    
    # Crear directorio de datos
    create_data_directory()
    
    print(f"\n🔍 Iniciando extracción de múltiples fuentes...")
    print(f"📊 Configuración: SWC Registry + Audit Reports + Blog Posts")
    
    all_entries = []
    
    # 1. Extraer SWCs
    print(f"\n📋 Extrayendo SWC Registry...")
    swc_extractor = ImprovedSWCExtractor()
    swc_entries = swc_extractor.extract_all_swcs(max_swcs=10)  # Limitar para testing
    all_entries.extend(swc_entries)
    print(f"✅ {len(swc_entries)} SWCs extraídos")
    
    # 2. Extraer Audit Reports (SOLO SOLIDITY)
    print(f"\n📋 Extrayendo Audit Reports (Solo Solidity)...")
    
    # Descubrimiento automático inteligente
    audit_extractor = AuditReportExtractor(target_language="solidity")
    
    # Descubrir automáticamente desde ConsenSys Diligence (LIMITADO)
    print("🔍 Descubriendo audit reports desde ConsenSys Diligence...")
    consensys_urls = audit_extractor.discover_audit_urls("https://diligence.consensys.io/audits/", max_pages=2)
    
    # Descubrir automáticamente desde Hacken.io (LIMITADO)
    print("🔍 Descubriendo audit reports desde Hacken.io...")
    hacken_urls = audit_extractor.discover_audit_urls("https://hacken.io/audits/", max_pages=1)
    
    # Combinar y LIMITAR URLs descubiertas
    all_urls = consensys_urls + hacken_urls
    # Eliminar duplicados y limitar a máximo 20 URLs
    audit_urls = list(set(all_urls))[:20]
    print(f"📋 Total de URLs descubiertas: {len(all_urls)}")
    print(f"📋 URLs únicas limitadas a: {len(audit_urls)}")
    
    # Extraer solo los audit reports de Solidity
    audit_entries = audit_extractor.extract_audits_from_list(audit_urls)
    all_entries.extend(audit_entries)
    print(f"✅ {len(audit_entries)} Audit Reports de Solidity extraídos")
    
    # 3. Extraer Blog Posts
    print(f"\n📋 Extrayendo Blog Posts...")
    blog_urls = [
        "https://blog.openzeppelin.com/reentrancy-after-istanbul/",
        "https://blog.trailofbits.com/2021/01/05/using-echidna-to-test-a-proxy-upgrade/"
    ]
    blog_extractor = BlogPostExtractor()
    blog_entries = blog_extractor.extract_blogs_from_list(blog_urls)
    all_entries.extend(blog_entries)
    print(f"✅ {len(blog_entries)} Blog Posts extraídos")
    
    entries = all_entries
    
    if entries:
        # Guardar en archivo
        knowledge_file = save_knowledge_base(entries)
        
        print(f"\n✅ EXTRACCIÓN COMPLETADA EXITOSAMENTE")
        print(f"📈 Estadísticas:")
        print(f"   • Total de entradas: {len(entries)}")
        print(f"   • Archivo de datos: {knowledge_file}")
        print(f"   • Archivo de log: {os.path.abspath(log_file)}")
        
        print(f"\n📋 RESUMEN DE CONTENIDO EXTRAÍDO:")
        print("-" * 50)
        
        # Agrupar por tipo de fuente
        swc_entries = [e for e in entries if e.source_type == "swc_registry"]
        audit_entries = [e for e in entries if e.source_type == "audit_report"]
        blog_entries = [e for e in entries if e.source_type == "blog_post"]
        
        if swc_entries:
            print(f"\n🔍 SWC Registry ({len(swc_entries)} entradas):")
            for entry in swc_entries[:3]:  # Mostrar solo los primeros 3
                print(f"  • {entry.id}: {entry.title}")
                print(f"    └─ Categoría: {entry.category} | Severidad: {entry.severity}")
        
        if audit_entries:
            print(f"\n📊 Audit Reports ({len(audit_entries)} entradas):")
            for entry in audit_entries:
                print(f"  • {entry.id}: {entry.title}")
                print(f"    └─ Categoría: {entry.category} | Severidad: {entry.severity}")
        
        if blog_entries:
            print(f"\n📝 Blog Posts ({len(blog_entries)} entradas):")
            for entry in blog_entries:
                print(f"  • {entry.id}: {entry.title}")
                print(f"    └─ Categoría: {entry.category} | Severidad: {entry.severity}")
        
        # Procesar chunking inteligente
        print(f"\n🧩 Iniciando chunking inteligente...")
        chunker = IntelligentChunker()
        chunks = chunker.chunk_knowledge_base(knowledge_file)
        
        if chunks:
            # Guardar chunks
            chunks_file = "data/chunks.jsonl"
            chunker.save_chunks(chunks, chunks_file)
            
            # Obtener estadísticas
            stats = chunker.get_chunk_statistics(chunks)
            
            print(f"✅ Chunking completado:")
            print(f"   • Total de chunks: {stats['total_chunks']}")
            print(f"   • Total de tokens: {stats['total_tokens']}")
            print(f"   • Promedio tokens/chunk: {stats['avg_tokens_per_chunk']:.1f}")
            print(f"   • Archivo de chunks: {os.path.abspath(chunks_file)}")
            
            print(f"\n📋 Distribución por tipo:")
            for chunk_type, count in stats['chunks_by_type'].items():
                print(f"   • {chunk_type}: {count}")
        
        print(f"\n🎯 PRÓXIMOS PASOS:")
        print(f"   1. Revisar datos en: {knowledge_file}")
        print(f"   2. Revisar chunks en: {os.path.abspath('data/chunks.jsonl')}")
        print(f"   3. Crear embeddings con OpenAI")
        print(f"   4. Integrar con Pinecone")
        
    else:
        print("❌ ERROR: No se pudieron extraer datos")
        print("🔍 Revisar el log para más detalles:", os.path.abspath(log_file))

if __name__ == "__main__":
    main()
