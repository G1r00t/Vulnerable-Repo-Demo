#!/bin/bash

# Clean setup script for AI-SAST Demo Application
# This script sets up the development environment with proper security practices

set -euo pipefail  # Exit on error, undefined vars, pipe failures

# Configuration
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
readonly LOG_FILE="$PROJECT_ROOT/setup.log"
readonly REQUIRED_NODE_VERSION="16"
readonly REQUIRED_PYTHON3_VERSION="3.8"

# Colors for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1" | tee -a "$LOG_FILE"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1" | tee -a "$LOG_FILE"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1" | tee -a "$LOG_FILE"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1" | tee -a "$LOG_FILE"
}

# Error handling
handle_error() {
    log_error "Setup failed at line $1"
    log_error "Check $LOG_FILE for details"
    exit 1
}

trap 'handle_error ${LINENO}' ERR

# Print banner
print_banner() {
    echo "=================================================="
    echo "  AI-SAST Demo Application Setup"
    echo "=================================================="
    echo ""
}

# Check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check system requirements
check_requirements() {
    log_info "Checking system requirements..."
    
    # Check Node.js
    if command_exists node; then
        local node_version
        node_version=$(node --version | sed 's/v//' | cut -d. -f1)
        if [ "$node_version" -ge "$REQUIRED_NODE_VERSION" ]; then
            log_success "Node.js $(node --version) is installed"
        else
            log_error "Node.js version $REQUIRED_NODE_VERSION or higher is required"
            exit 1
        fi
    else
        log_error "Node.js is not installed"
        exit 1
    fi
    
    # Check Python
    if command_exists python3; then
        local python_version
        python_version=$(python3 --version | cut -d' ' -f2 | cut -d. -f1,2)
        if [ "$(echo "$python_version >= $REQUIRED_PYTHON_VERSION" | bc)" -eq 1 ]; then
            log_success "Python $(python3 --version) is installed"
        else
            log_error "Python version $REQUIRED_PYTHON_VERSION or higher is required"
            exit 1
        fi
    else
        log_error "Python 3 is not installed"
        exit 1
    fi
    
    # Check npm
    if command_exists npm; then
        log_success "npm $(npm --version) is installed"
    else
        log_error "npm is not installed"
        exit 1
    fi
    
    # Check pip
    if command_exists pip3; then
        log_success "pip3 is installed"
    else
        log_error "pip3 is not installed"
        exit 1
    fi
    
    # Check Docker (optional)
    if command_exists docker; then
        log_success "Docker $(docker --version | cut -d' ' -f3 | sed 's/,//') is installed"
    else
        log_warning "Docker is not installed (optional for development)"
    fi
    
    # Check Git
    if command_exists git; then
        log_success "Git $(git --version | cut -d' ' -f3) is installed"
    else
        log_error "Git is not installed"
        exit 1
    fi
}

# Create necessary directories
create_directories() {
    log_info "Creating project directories..."
    
    local directories=(
        "$PROJECT_ROOT/logs"
        "$PROJECT_ROOT/uploads"
        "$PROJECT_ROOT/temp"
        "$PROJECT_ROOT/data"
        "$PROJECT_ROOT/backups"
        "$PROJECT_ROOT/.env.d"
    )
    
    for dir in "${directories[@]}"; do
        if [ ! -d "$dir" ]; then
            mkdir -p "$dir"
            log_success "Created directory: $dir"
        else
            log_info "Directory already exists: $dir"
        fi
    done
    
    # Set proper permissions
    chmod 755 "$PROJECT_ROOT/logs"
    chmod 755 "$PROJECT_ROOT/uploads"
    chmod 700 "$PROJECT_ROOT/temp"
    chmod 700 "$PROJECT_ROOT/.env.d"
}

# Install Node.js dependencies
install_node_dependencies() {
    log_info "Installing Node.js dependencies..."
    
    cd "$PROJECT_ROOT"
    
    # Install frontend dependencies
    if [ -f "package.json" ]; then
        npm ci --production=false
        log_success "Installed Node.js dependencies"
    else
        log_warning "No package.json found in project root"
    fi
    
    # Install frontend-specific dependencies
    if [ -f "frontend/package.json" ]; then
        cd "$PROJECT_ROOT/frontend"
        npm ci --production=false
        log_success "Installed frontend dependencies"
        cd "$PROJECT_ROOT"
    fi
}

# Install Python dependencies
install_python_dependencies() {
    log_info "Installing Python dependencies..."
    
    cd "$PROJECT_ROOT"
    
    # Create virtual environment if it doesn't exist
    if [ ! -d "venv" ]; then
        python3 -m venv venv
        log_success "Created Python virtual environment"
    fi
    
    # Activate virtual environment and install dependencies
    source venv/bin/activate
    
    if [ -f "requirements.txt" ]; then
        pip install --upgrade pip
        pip install -r requirements.txt
        log_success "Installed Python dependencies"
    else
        log_warning "No requirements.txt found"
    fi
    
    # Install development dependencies
    if [ -f "requirements-dev.txt" ]; then
        pip install -r requirements-dev.txt
        log_success "Installed Python development dependencies"
    fi
    
    deactivate
}

# Setup environment files
setup_environment() {
    log_info "Setting up environment configuration..."
    
    # Copy environment templates
    if [ -f "$PROJECT_ROOT/.env.example" ] && [ ! -f "$PROJECT_ROOT/.env" ]; then
        cp "$PROJECT_ROOT/.env.example" "$PROJECT_ROOT/.env"
        log_success "Created .env file from template"
        log_warning "Please update .env file with your configuration"
    fi
    
    # Generate random secrets for development
    if command_exists openssl; then
        local jwt_secret
        local session_secret
        local encryption_key
        
        jwt_secret=$(openssl rand -hex 32)
        session_secret=$(openssl rand -hex 32)
        encryption_key=$(openssl rand -hex 32)
        
        # Update .env with generated secrets (if not already set)
        if [ -f "$PROJECT_ROOT/.env" ]; then
            if ! grep -q "JWT_SECRET=" "$PROJECT_ROOT/.env"; then
                echo "JWT_SECRET=$jwt_secret" >> "$PROJECT_ROOT/.env"
            fi
            if ! grep -q "SESSION_SECRET=" "$PROJECT_ROOT/.env"; then
                echo "SESSION_SECRET=$session_secret" >> "$PROJECT_ROOT/.env"
            fi
            if ! grep -q "ENCRYPTION_KEY=" "$PROJECT_ROOT/.env"; then
                echo "ENCRYPTION_KEY=$encryption_key" >> "$PROJECT_ROOT/.env"
            fi
            log_success "Generated secure secrets for development"
        fi
    else
        log_warning "OpenSSL not found - using default secrets (not recommended)"
    fi
}

# Setup database (if Docker is available)
setup_database() {
    if command_exists docker && command_exists docker-compose; then
        log_info "Setting up development database..."
        
        if [ -f "$PROJECT_ROOT/docker-compose.yml" ]; then
            cd "$PROJECT_ROOT"
            docker-compose up -d db redis
            log_success "Started development database services"
            
            # Wait for database to be ready
            log_info "Waiting for database to be ready..."
            sleep 10
            
            # Run database migrations
            if [ -f "backend/migrations/run_migrations.py" ]; then
                source venv/bin/activate
                python3 backend/migrations/run_migrations.py
                deactivate
                log_success "Applied database migrations"
            fi
        else
            log_warning "No docker-compose.yml found - skipping database setup"
        fi
    else
        log_warning "Docker not available - skipping database setup"
        log_info "Please set up PostgreSQL and Redis manually"
    fi
}

# Run tests to verify setup
run_tests() {
    log_info "Running verification tests..."
    
    cd "$PROJECT_ROOT"
    
    # Run Python tests
    if [ -f "backend/tests/test_setup.py" ]; then
        source venv/bin/activate
        python3 -m pytest backend/tests/test_setup.py -v
        deactivate
        log_success "Python setup tests passed"
    fi
    
    # Run Node.js tests
    if [ -f "frontend/package.json" ]; then
        cd "$PROJECT_ROOT/frontend"
        npm test -- --watchAll=false --ci
        cd "$PROJECT_ROOT"
        log_success "Node.js setup tests passed"
    fi
}

# Setup development tools
setup_dev_tools() {
    log_info "Setting up development tools..."
    
    # Setup pre-commit hooks
    if [ -f ".pre-commit-config.yaml" ]; then
        source venv/bin/activate
        pre-commit install
        deactivate
        log_success "Installed pre-commit hooks"
    fi
    
    # Setup ESLint and Prettier for frontend
    if [ -f "frontend/.eslintrc.js" ]; then
        log_success "ESLint configuration found"
    fi
    
    if [ -f "frontend/.prettierrc" ]; then
        log_success "Prettier configuration found"
    fi
    
    # Setup Python linting tools
    if command_exists black && command_exists flake8; then
        log_success "Python linting tools available"
    fi
}

# Print setup completion
print_completion() {
    echo ""
    echo "=================================================="
    echo "  Setup Completed Successfully!"
    echo "=================================================="
    echo ""
    echo "Next steps:"
    echo "1. Update .env file with your configuration"
    echo "2. Start the development server:"
    echo "   - Backend: cd backend && source ../venv/bin/activate && python3 app.py"
    echo "   - Frontend: cd frontend && npm start"
    echo "3. Visit http://localhost:3000 to view the application"
    echo ""
    echo "Useful commands:"
    echo "- Run tests: npm test (frontend) or pytest (backend)"
    echo "- Lint code: npm run lint (frontend) or flake8 (backend)"
    echo "- View logs: tail -f logs/app.log"
    echo ""
    echo "For more information, see README.md"
    echo ""
}

# Cleanup function
cleanup() {
    log_info "Cleaning up temporary files..."
    
    # Remove any temporary files created during setup
    find "$PROJECT_ROOT" -name "*.pyc" -delete 2>/dev/null || true
    find "$PROJECT_ROOT" -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true
    find "$PROJECT_ROOT" -name ".pytest_cache" -type d -exec rm -rf {} + 2>/dev/null || true
    find "$PROJECT_ROOT" -name "node_modules/.cache" -type d -exec rm -rf {} + 2>/dev/null || true
    
    log_success "Cleanup completed"
}

# Main setup function
main() {
    print_banner
    
    # Initialize log file
    echo "Setup started at $(date)" > "$LOG_FILE"
    
    # Run setup steps
    check_requirements
    create_directories
    install_node_dependencies
    install_python_dependencies
    setup_environment
    setup_database
    setup_dev_tools
    run_tests
    cleanup
    
    print_completion
    
    log_success "Setup completed successfully at $(date)"
}

# Handle script arguments
case "${1:-}" in
    --help|-h)
        echo "Usage: $0 [OPTIONS]"
        echo ""
        echo "Options:"
        echo "  --help, -h     Show this help message"
        echo "  --check        Only check requirements"
        echo "  --deps         Only install dependencies"
        echo "  --clean        Clean up project files"
        echo ""
        echo "This script sets up the AI-SAST Demo development environment."
        exit 0
        ;;
    --check)
        print_banner
        check_requirements
        log_success "Requirements check completed"
        exit 0
        ;;
    --deps)
        print_banner
        install_node_dependencies
        install_python_dependencies
        log_success "Dependencies installation completed"
        exit 0
        ;;
    --clean)
        print_banner
        cleanup
        exit 0
        ;;
    "")
        # No arguments - run full setup
        main
        ;;
    *)
        log_error "Unknown option: $1"
        echo "Use --help for usage information"
        exit 1
        ;;
esac