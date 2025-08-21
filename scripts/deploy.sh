#!/bin/bash

# Black Glove Deployment Script
# Simplified deployment for home security testing

set -e  # Exit on any error

echo "🚀 Black Glove Deployment Script"
echo "================================"

# Check if running on supported platform
if [[ "$OSTYPE" == "msys" ]] || [[ "$OSTYPE" == "win32" ]]; then
    echo "Windows detected - using PowerShell commands"
    IS_WINDOWS=1
else
    echo "Unix-like system detected"
    IS_WINDOWS=0
fi

# Function to check prerequisites
check_prerequisites() {
    echo "🔍 Checking prerequisites..."
    
    # Check Python
    if ! command -v python3 &> /dev/null && ! command -v python &> /dev/null; then
        echo "❌ Python 3.8+ is required but not found"
        exit 1
    fi
    echo "✅ Python found"
    
    # Check Docker
    if ! command -v docker &> /dev/null; then
        echo "❌ Docker is required but not found"
        echo "   Please install Docker Desktop from https://www.docker.com/products/docker-desktop"
        exit 1
    fi
    echo "✅ Docker found"
    
    # Check if Docker is running
    if ! docker info &> /dev/null; then
        echo "❌ Docker is not running"
        echo "   Please start Docker Desktop"
        exit 1
    fi
    echo "✅ Docker is running"
    
    echo "✅ All prerequisites met"
}

# Function to setup virtual environment
setup_venv() {
    echo "🐍 Setting up Python virtual environment..."
    
    if [ $IS_WINDOWS -eq 1 ]; then
        python -m venv .venv
        source .venv/Scripts/activate
    else
        python3 -m venv .venv
        source .venv/bin/activate
    fi
    
    echo "✅ Virtual environment created and activated"
}

# Function to install dependencies
install_dependencies() {
    echo "📦 Installing dependencies..."
    
    if [ $IS_WINDOWS -eq 1 ]; then
        .venv/Scripts/pip install --upgrade pip
        .venv/Scripts/pip install -e .
    else
        .venv/bin/pip install --upgrade pip
        .venv/bin/pip install -e .
    fi
    
    echo "✅ Dependencies installed"
}

# Function to run tests
run_tests() {
    echo "🧪 Running tests..."
    
    if [ $IS_WINDOWS -eq 1 ]; then
        .venv/Scripts/python -m pytest tests/ -v
    else
        .venv/bin/python -m pytest tests/ -v
    fi
    
    echo "✅ Tests passed"
}

# Function to create deployment package
create_package() {
    echo "📦 Creating deployment package..."
    
    # Create deployment directory
    mkdir -p deploy/black_glove
    
    # Copy essential files
    cp -r src deploy/black_glove/
    cp -r config deploy/black_glove/
    cp README.md deploy/black_glove/
    cp LICENSE deploy/black_glove/
    cp pyproject.toml deploy/black_glove/
    
    # Create simple runner script
    if [ $IS_WINDOWS -eq 1 ]; then
        cat > deploy/black_glove/run.bat << 'EOF'
@echo off
python -m venv .venv
.venv\Scripts\pip install -e .
echo Black Glove is ready! Run with: .venv\Scripts\python -m src.agent
EOF
    else
        cat > deploy/black_glove/run.sh << 'EOF'
#!/bin/bash
python3 -m venv .venv
.venv/bin/pip install -e .
echo "Black Glove is ready! Run with: .venv/bin/python -m src.agent"
EOF
        chmod +x deploy/black_glove/run.sh
    fi
    
    echo "✅ Deployment package created in deploy/black_glove/"
}

# Function to show usage
show_usage() {
    echo "Usage: $0 [options]"
    echo "Options:"
    echo "  --check-only    Check prerequisites only"
    echo "  --setup         Setup environment and install dependencies"
    echo "  --test          Run tests"
    echo "  --package       Create deployment package"
    echo "  --full          Run full deployment process (default)"
    echo "  --help          Show this help message"
}

# Main deployment function
main() {
    local action="full"
    
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --check-only)
                action="check"
                shift
                ;;
            --setup)
                action="setup"
                shift
                ;;
            --test)
                action="test"
                shift
                ;;
            --package)
                action="package"
                shift
                ;;
            --full)
                action="full"
                shift
                ;;
            --help|-h)
                show_usage
                exit 0
                ;;
            *)
                echo "Unknown option: $1"
                show_usage
                exit 1
                ;;
        esac
    done
    
    # Execute requested action
    case $action in
        check)
            check_prerequisites
            ;;
        setup)
            check_prerequisites
            setup_venv
            install_dependencies
            ;;
        test)
            check_prerequisites
            setup_venv
            install_dependencies
            run_tests
            ;;
        package)
            check_prerequisites
            setup_venv
            install_dependencies
            create_package
            ;;
        full)
            check_prerequisites
            setup_venv
            install_dependencies
            run_tests
            create_package
            echo "🎉 Full deployment completed successfully!"
            echo ""
            echo "Next steps:"
            echo "1. Review the deployment package in deploy/black_glove/"
            echo "2. Run the agent with: cd deploy/black_glove && ./run.sh"
            echo "3. Initialize with: python -m src.agent init"
            ;;
    esac
}

# Run main function
main "$@"
