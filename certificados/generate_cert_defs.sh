#!/usr/bin/env bash
set -euo pipefail

# Salida final y archivo temporal
OUT="cert_defs.h"
TMP="$(mktemp)"

# 1) Cabecera en el temporal
cat > "$TMP" << 'EOF'
#ifndef CERT_DEFS_H
#define CERT_DEFS_H

/* ----- CA root (pública) -------------------------------------------- */
EOF

# 2) Bucle para cada .bin (siempre escribe en $TMP)
for name in ca_pub srv_priv srv_cert; do
  # Nombre de la variable en mayúsculas
  var=$(echo "$name" | tr '[:lower:]' '[:upper:]')

  # Línea en blanco para separar secciones
  echo >> "$TMP"

  # Volcado con xxd -i y renombrado de las variables
  xxd -i "${name}.bin" | \
    sed "s/unsigned char ${name}_bin\\[\\]/static const uint8_t ${var}\\[\\]/" | \
    sed "s/unsigned int ${name}_bin_len/static const size_t ${var}_LEN/" >> "$TMP"
done

# 3) Pie de fichero
cat >> "$TMP" << 'EOF'

/* ----- Parámetros varios ------------------------------------------- */
#define CLI_CERT_LEN 1312         /* cli_cert.bin (debe coincidir)      */
#endif /* CERT_DEFS_H */
EOF

# 4) Sustituye la salida antigua sólo al final
mv "$TMP" "$OUT"
echo "-> $OUT generado correctamente."
