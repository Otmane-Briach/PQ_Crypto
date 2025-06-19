#!/usr/bin/env bash
set -euo pipefail

# Ficheros de entrada
CA_BIN="ca_pub.bin"
CLI_BIN="cli_cert.bin"

# Salida final y archivo temporal
OUT="cert_defs_client.h"
TMP="$(mktemp)"

# 1) Cabecera en el temporal
cat > "$TMP" << 'EOF'
#ifndef CERT_DEFS_H
#define CERT_DEFS_H

#include <stddef.h>
#include <stdint.h>

 
EOF

# Función para volcar un .bin a un array C en el temporal
dump_bin() {
  local binfile=$1
  local varname=$2
  local length

  length=$(stat -c%s "$binfile")

  echo "" >> "$TMP"
  echo "static const uint8_t ${varname}[] = {" >> "$TMP"
  xxd -i "$binfile" | sed "s/^/    /" >> "$TMP"
  echo "};" >> "$TMP"
  echo "static const size_t ${varname}_LEN = $length;" >> "$TMP"
  echo "" >> "$TMP"
}

# 2) Volcar ca_pub.bin → CA_PUB
dump_bin "$CA_BIN" "CA_PUB"

# 3) Volcar cli_cert.bin → CLI_CERT
dump_bin "$CLI_BIN" "CLI_CERT"

# 4) Pie de fichero
cat >> "$TMP" << 'EOF'
#endif /* CERT_DEFS_H */
EOF

# 5) Sustituye la salida antigua sólo al final
mv "$TMP" "$OUT"
echo "-> $OUT generado correctamente."
