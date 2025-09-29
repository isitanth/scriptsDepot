#!/bin/bash
# Convolution Explorer - Build & Cleanup Script
# Compatible with macOS and other Unix-like systems
# This script helps build the project and clean up all compiled artifacts

set -e  # Exit on any error

# Colors for output (macOS compatible)
if [[ -t 1 ]]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    BLUE='\033[0;34m'
    BOLD='\033[1m'
    NC='\033[0m' # No Color
else
    RED=''
    GREEN=''
    YELLOW=''
    BLUE=''
    BOLD=''
    NC=''
fi

# Project information
PROJECT_NAME="Convolution Explorer"
VERSION="1.0.0"

# Script directory (where this script is located)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Build directories created by make
BUILD_DIRS=("bin" "obj" "lib")

# Files that might be created during build/development
TEMP_FILES=(
    "*.o"
    "*.so" 
    "*.a"
    "*.dylib"
    "core"
    "*.core"
    ".DS_Store"
    "*.dSYM"
    "*.log"
    "*.tmp"
)

# Function to print colored output
print_header() {
    echo -e "${BOLD}${BLUE}╔══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BOLD}${BLUE}║                    $PROJECT_NAME                    ║${NC}"
    echo -e "${BOLD}${BLUE}║                   Build & Cleanup Script                ║${NC}"
    echo -e "${BOLD}${BLUE}║                      Version $VERSION                       ║${NC}"
    echo -e "${BOLD}${BLUE}╚══════════════════════════════════════════════════════════╝${NC}"
    echo
}

print_success() {
    echo -e "${GREEN}✓${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

print_info() {
    echo -e "${BLUE}ℹ${NC} $1"
}

# Function to check system requirements
check_requirements() {
    print_info "Checking system requirements..."
    
    # Check for GCC
    if ! command -v gcc >/dev/null 2>&1; then
        print_error "GCC compiler not found. Please install Xcode Command Line Tools:"
        echo "  xcode-select --install"
        exit 1
    fi
    print_success "GCC compiler found: $(gcc --version | head -1)"
    
    # Check for make
    if ! command -v make >/dev/null 2>&1; then
        print_error "Make utility not found. Please install build tools."
        exit 1
    fi
    print_success "Make utility found: $(make --version | head -1)"
    
    # Check if we're in the right directory
    if [[ ! -f "Makefile" ]]; then
        print_error "Makefile not found. Make sure you're running this script from the project root directory."
        exit 1
    fi
    print_success "Project structure verified"
    
    echo
}

# Function to show current build status
show_status() {
    print_info "Current build status:"
    
    local has_artifacts=false
    
    # Check for build directories
    for dir in "${BUILD_DIRS[@]}"; do
        if [[ -d "$dir" ]]; then
            local file_count=$(find "$dir" -type f 2>/dev/null | wc -l | tr -d ' ')
            if [[ $file_count -gt 0 ]]; then
                echo "  📁 $dir/ ($file_count files)"
                has_artifacts=true
            fi
        fi
    done
    
    # Check for temporary files
    local temp_count=0
    for pattern in "${TEMP_FILES[@]}"; do
        if ls $pattern >/dev/null 2>&1; then
            temp_count=$((temp_count + $(ls $pattern 2>/dev/null | wc -l)))
        fi
    done
    
    if [[ $temp_count -gt 0 ]]; then
        echo "  🗑️  Temporary files found: $temp_count"
        has_artifacts=true
    fi
    
    if [[ "$has_artifacts" == false ]]; then
        print_success "Project is clean (no build artifacts found)"
    fi
    
    echo
}

# Function to build the project
build_project() {
    local build_type="${1:-all}"
    
    print_info "Building project ($build_type)..."
    echo
    
    case $build_type in
        "all")
            make all
            ;;
        "debug")
            make debug
            ;;
        "release")
            make release
            ;;
        "examples")
            make examples
            ;;
        "main")
            make bin/convolution_explorer
            ;;
        *)
            print_error "Unknown build type: $build_type"
            return 1
            ;;
    esac
    
    echo
    print_success "Build completed successfully!"
    
    # Show what was built
    if [[ -d "bin" ]]; then
        print_info "Executables created:"
        for exe in bin/*; do
            if [[ -f "$exe" && -x "$exe" ]]; then
                local size=$(ls -lh "$exe" | awk '{print $5}')
                echo "  🚀 $exe ($size)"
            fi
        done
        echo
    fi
}

# Function to run the main application
run_application() {
    local exe_path="bin/convolution_explorer"
    
    if [[ ! -f "$exe_path" ]]; then
        print_warning "Main executable not found. Building first..."
        build_project "main"
    fi
    
    if [[ -f "$exe_path" && -x "$exe_path" ]]; then
        print_info "Running $PROJECT_NAME..."
        echo
        ./"$exe_path"
    else
        print_error "Failed to build or find executable"
        return 1
    fi
}

# Function to clean build artifacts
clean_project() {
    local force="${1:-false}"
    
    print_info "Cleaning build artifacts..."
    
    # Use make clean first (safest approach)
    if [[ -f "Makefile" ]]; then
        print_info "Running 'make clean'..."
        make clean 2>/dev/null || true
    fi
    
    # Additional cleanup for any remaining artifacts
    local cleaned_items=0
    
    # Remove build directories if they exist and are empty or contain only build artifacts
    for dir in "${BUILD_DIRS[@]}"; do
        if [[ -d "$dir" ]]; then
            print_info "Removing directory: $dir/"
            rm -rf "$dir"
            cleaned_items=$((cleaned_items + 1))
        fi
    done
    
    # Remove temporary files
    for pattern in "${TEMP_FILES[@]}"; do
        if ls $pattern >/dev/null 2>&1; then
            local files_found=$(ls $pattern 2>/dev/null)
            for file in $files_found; do
                if [[ -f "$file" ]]; then
                    print_info "Removing temporary file: $file"
                    rm -f "$file"
                    cleaned_items=$((cleaned_items + 1))
                fi
            done
        fi
    done
    
    # Remove any .dSYM directories (macOS debug symbols)
    find . -name "*.dSYM" -type d -exec rm -rf {} + 2>/dev/null || true
    
    if [[ $cleaned_items -gt 0 ]]; then
        print_success "Cleaned $cleaned_items items"
    else
        print_success "Project was already clean"
    fi
    
    echo
    print_success "Project restored to original clean state"
    print_info "All compiled files have been removed. The project is ready for:"
    echo "  • Fresh cloning/downloading"
    echo "  • Version control operations"
    echo "  • Distribution packaging"
    echo
}

# Function to show help
show_help() {
    cat << EOF
Usage: $0 [COMMAND] [OPTIONS]

COMMANDS:
    build [TYPE]     Build the project
                     Types: all (default), debug, release, examples, main
    
    run             Build (if needed) and run the main application
    
    clean           Remove all build artifacts and restore to clean state
    
    status          Show current build status
    
    help            Show this help message
    
    interactive     Run in interactive mode (default if no command given)

EXAMPLES:
    $0 build            # Build everything (default)
    $0 build debug      # Build with debug symbols
    $0 build release    # Build optimized release version
    $0 run              # Build and run the application
    $0 clean            # Clean all build artifacts
    $0 status           # Check current build status

NOTES:
    • This script maintains the project in its original state when cleaning
    • All build artifacts are removed completely during cleanup
    • The script checks for required tools (GCC, make) before building
    • Compatible with macOS and other Unix-like systems

EOF
}

# Interactive mode
interactive_mode() {
    while true; do
        print_header
        show_status
        
        echo -e "${BOLD}What would you like to do?${NC}"
        echo "1) Build project (all)"
        echo "2) Build debug version"
        echo "3) Build release version"
        echo "4) Build examples only"
        echo "5) Run application"
        echo "6) Clean project"
        echo "7) Show build status"
        echo "8) Show help"
        echo "9) Exit"
        echo
        read -p "Enter your choice (1-9): " choice
        
        case $choice in
            1)
                echo
                build_project "all"
                read -p "Press Enter to continue..."
                ;;
            2)
                echo
                build_project "debug"
                read -p "Press Enter to continue..."
                ;;
            3)
                echo
                build_project "release"
                read -p "Press Enter to continue..."
                ;;
            4)
                echo
                build_project "examples"
                read -p "Press Enter to continue..."
                ;;
            5)
                echo
                run_application
                read -p "Press Enter to continue..."
                ;;
            6)
                echo
                echo -e "${YELLOW}This will remove all compiled files and restore the project to its original clean state.${NC}"
                read -p "Are you sure? (y/N): " confirm
                if [[ $confirm =~ ^[Yy]$ ]]; then
                    clean_project
                else
                    print_info "Clean operation cancelled"
                fi
                read -p "Press Enter to continue..."
                ;;
            7)
                echo
                show_status
                read -p "Press Enter to continue..."
                ;;
            8)
                clear
                show_help
                read -p "Press Enter to continue..."
                ;;
            9)
                print_info "Goodbye!"
                exit 0
                ;;
            *)
                print_error "Invalid choice. Please enter a number between 1-9."
                read -p "Press Enter to continue..."
                ;;
        esac
        
        clear
    done
}

# Main script logic
main() {
    # Always check requirements first
    check_requirements
    
    # Handle command line arguments
    case "${1:-}" in
        "build")
            build_project "${2:-all}"
            ;;
        "run")
            run_application
            ;;
        "clean")
            clean_project
            ;;
        "status")
            show_status
            ;;
        "help"|"--help"|"-h")
            show_help
            ;;
        "")
            # No arguments - run in interactive mode
            interactive_mode
            ;;
        *)
            print_error "Unknown command: $1"
            echo
            show_help
            exit 1
            ;;
    esac
}

# Trap to handle Ctrl+C gracefully
trap 'echo -e "\n${YELLOW}Operation cancelled by user${NC}"; exit 1' INT

# Run the main function with all arguments
main "$@"