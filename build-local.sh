#!/bin/bash
set -e

echo "============================================"
echo "  GhidraMCP - Build Local (Ghidra 12.0.1)"
echo "============================================"
echo

PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
SRC_DIR="$PROJECT_DIR/src/main/java"
RES_DIR="$PROJECT_DIR/src/main/resources"
LIB_DIR="$PROJECT_DIR/lib"
BIN_DIR="$PROJECT_DIR/target/classes"
OUT_DIR="$PROJECT_DIR/target"
STAGE_DIR="$PROJECT_DIR/target/stage"
JAR_NAME="GhidraMCP.jar"
ZIP_NAME="GhidraMCP-1.0-SNAPSHOT.zip"

# Detectar JDK 21+ com jar disponivel (javapath da Oracle nao tem jar)
JDK_CANDIDATES=(
    "$JAVA_HOME"
    "/c/Program Files/Java/jdk-25.0.2"
    "/c/Program Files/Java/jdk-24"
    "/c/Program Files/Java/jdk-21"
    "/c/Program Files/Java/latest"
)
JAVAC=""
JAR_CMD=""
for jdk in "${JDK_CANDIDATES[@]}"; do
    [ -z "$jdk" ] && continue
    if [ -x "$jdk/bin/javac.exe" ] && [ -x "$jdk/bin/jar.exe" ]; then
        JAVAC="$jdk/bin/javac.exe"
        JAR_CMD="$jdk/bin/jar.exe"
        break
    fi
done
[ -n "$JAVAC_OVERRIDE" ] && JAVAC="$JAVAC_OVERRIDE"
[ -n "$JAR_OVERRIDE" ] && JAR_CMD="$JAR_OVERRIDE"

if ! command -v "$JAVAC" >/dev/null 2>&1 && [ ! -x "$JAVAC" ]; then
    echo "[ERRO] javac nao encontrado. Defina JAVAC_OVERRIDE."
    exit 1
fi

echo "  javac : $($JAVAC -version 2>&1)"
echo "  lib/  : $(ls $LIB_DIR/*.jar 2>/dev/null | wc -l | tr -d ' ') JARs do Ghidra"
echo

# --- Sanity check: lib/ precisa ter os 12 JARs do Ghidra (8 base + 4 debugger) ---
MISSING=0
for jar in Base.jar Decompiler.jar Docking.jar Generic.jar Gui.jar Project.jar SoftwareModeling.jar Utility.jar \
           Debugger.jar Debugger-api.jar Framework-TraceModeling.jar ProposedUtils.jar; do
    if [ ! -f "$LIB_DIR/$jar" ]; then
        echo "  [ERRO] Faltando $LIB_DIR/$jar"
        MISSING=1
    fi
done
[ "$MISSING" -eq 1 ] && exit 1

# --- Montar classpath (caminhos Windows p/ javac.exe) ---
CP=""
for jar in "$LIB_DIR"/*.jar; do
    winjar=$(cygpath -w "$jar")
    [ -z "$CP" ] && CP="$winjar" || CP="$CP;$winjar"
done

# --- Compilar (Ghidra 12.0.1 roda em Java 21 LTS) ---
echo "[1/4] Compilando com --release 21..."
rm -rf "$BIN_DIR"
mkdir -p "$BIN_DIR"

SOURCES_FILE="$PROJECT_DIR/.sources.txt"
find "$SRC_DIR" -name "*.java" | while read f; do cygpath -w "$f"; done > "$SOURCES_FILE"
TOTAL=$(wc -l < "$SOURCES_FILE" | tr -d ' ')

"$JAVAC" --release 21 -encoding UTF-8 -Xlint:-options \
    -cp "$CP" -d "$(cygpath -w "$BIN_DIR")" @"$(cygpath -w "$SOURCES_FILE")"
rm -f "$SOURCES_FILE"

COUNT=$(find "$BIN_DIR" -name "*.class" | wc -l | tr -d ' ')
echo "        $COUNT/$TOTAL classes compiladas."
echo

# --- Empacotar JAR usando MANIFEST.MF customizado ---
echo "[2/4] Empacotando $JAR_NAME..."
rm -f "$OUT_DIR/$JAR_NAME"
"$JAR_CMD" cfm "$OUT_DIR/$JAR_NAME" \
    "$RES_DIR/META-INF/MANIFEST.MF" \
    -C "$BIN_DIR" .
JAR_SIZE=$(du -k "$OUT_DIR/$JAR_NAME" | cut -f1)
echo "        target/$JAR_NAME (${JAR_SIZE} KB)"
echo

# --- Montar estrutura da extensao Ghidra ---
echo "[3/4] Montando estrutura GhidraMCP/..."
rm -rf "$STAGE_DIR"
mkdir -p "$STAGE_DIR/GhidraMCP/lib"
cp "$RES_DIR/extension.properties" "$STAGE_DIR/GhidraMCP/"
cp "$RES_DIR/Module.manifest" "$STAGE_DIR/GhidraMCP/"
cp "$OUT_DIR/$JAR_NAME" "$STAGE_DIR/GhidraMCP/lib/"
echo "        Estrutura montada."
echo

# --- Criar ZIP (jar.exe usa '/' como separador, como exige a spec do ZIP;
#     Compress-Archive do PowerShell grava '\' e quebra o ExtensionUtils do Ghidra) ---
echo "[4/4] Criando $ZIP_NAME..."
rm -f "$OUT_DIR/$ZIP_NAME"
if command -v zip >/dev/null 2>&1; then
    (cd "$STAGE_DIR" && zip -qr "$OUT_DIR/$ZIP_NAME" GhidraMCP)
else
    # jar.exe --create --no-manifest --file=... -C <dir> .
    WIN_ZIP=$(cygpath -w "$OUT_DIR/$ZIP_NAME")
    WIN_STAGE=$(cygpath -w "$STAGE_DIR")
    "$JAR_CMD" --create --no-manifest --file="$WIN_ZIP" -C "$WIN_STAGE" GhidraMCP
fi
ZIP_SIZE=$(du -k "$OUT_DIR/$ZIP_NAME" | cut -f1)
echo "        target/$ZIP_NAME (${ZIP_SIZE} KB)"
echo

echo "============================================"
echo "  Extensao pronta: $OUT_DIR/$ZIP_NAME"
echo "  Instalar no Ghidra: File > Install Extensions > +"
echo "============================================"
