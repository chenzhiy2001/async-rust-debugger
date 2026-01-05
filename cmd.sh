# frequently used commands

if [ "$1" = "compile-tests" ]; then
    case "$2" in
        minimal)
            echo "Compiling testcases (minimal)..."
            cd testcases/minimal
            cargo build
            ;;
        no_external_future)
            echo "Compiling testcases (no_external_future)..."
            cd testcases/no_external_future
            cargo build
            ;;
        *)
            echo "Usage: $0 compile-all-testcases {minimal|no_external_future}" >&2
            exit 2
            ;;
    esac
fi