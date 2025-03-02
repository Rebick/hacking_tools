#!/bin/bash
#Despues de httpx -l subdominios_up --sc -o httpx.txt -v
# Verificar si se proporcionó un archivo como argumento
if [ "$#" -ne 1 ]; then
    echo "Uso: $0 <archivo>"
    exit 1
fi

archivo="$1"

# Verificar si el archivo existe
if [ ! -f "$archivo" ]; then
    echo "El archivo $archivo no existe."
    exit 1
fi

# Contar respuestas por tipo
count_20x=$(grep -E "20[0-9]" "$archivo" | wc -l)
count_30x=$(grep -E "30[0-9]" "$archivo" | wc -l)
count_40x=$(grep -E "40[0-9]" "$archivo" | wc -l)

# Mostrar resultados
echo "Resumen de códigos de respuesta:"
echo "20X: $count_20x"
echo "30X: $count_30x"
echo "40X: $count_40x"
