build:
    GOOS=js GOARCH=wasm go build -o app.wasm .
    @if [ -f "$(go env GOROOT)/misc/wasm/wasm_exec.js" ]; then \
        cp -f "$(go env GOROOT)/misc/wasm/wasm_exec.js" .; \
    elif [ -f "$(go env GOROOT)/lib/wasm/wasm_exec.js" ]; then \
        cp -f "$(go env GOROOT)/lib/wasm/wasm_exec.js" .; \
    else \
        echo "wasm_exec.js not found in GOROOT" >&2; \
        exit 1; \
    fi

serve: build
    python3 -m http.server 8000

clean:
    rm -f app.wasm wasm_exec.js
