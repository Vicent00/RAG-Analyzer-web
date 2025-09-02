# SWC Registry RAG System

Sistema RAG (Retrieval-Augmented Generation) para análisis de vulnerabilidades de smart contracts basado en el SWC Registry.

## 🚀 Características

- **Extractor Profesional**: Extrae datos estructurados del SWC Registry
- **Categorización Inteligente**: Clasifica automáticamente vulnerabilidades
- **Metadatos Enriquecidos**: Extrae CWE IDs, severidad y tags
- **Contenido Limpio**: Elimina elementos de navegación innecesarios

## 📁 Estructura del Proyecto

```
Scrappear-info-web/
├── data/
│   ├── schema.py              # Esquema universal de datos
│   └── knowledge_base.jsonl   # Base de conocimiento extraída
├── extractors/
│   ├── __init__.py
│   └── swc_extractor.py      # Extractor mejorado del SWC Registry
├── logs/                     # Archivos de log de extracción
├── main.py                   # Script principal de extracción
├── requirements.txt          # Dependencias
├── .gitignore               # Archivos a ignorar en Git
└── README.md
```

## 🛠️ Instalación

1. Instalar dependencias:
```bash
pip install -r requirements.txt
```

2. Ejecutar extracción:
```bash
python main.py
```

## 📊 Datos Extraídos

Cada entrada incluye:
- **ID único**: swc_SWC-XXX
- **Título descriptivo**: Nombre real de la vulnerabilidad
- **Categoría**: Tipo de vulnerabilidad (reentrancy, integer-overflow, etc.)
- **Severidad**: low, medium, high
- **CWE ID**: Clasificación CWE correspondiente
- **Contenido estructurado**: Descripción, remediación, referencias, código
- **Tags**: Etiquetas para búsqueda y filtrado

## 🔄 Próximos Pasos

- [ ] Implementar chunking inteligente
- [ ] Integrar embeddings con OpenAI
- [ ] Conectar con Pinecone
- [ ] Construir sistema RAG completo
