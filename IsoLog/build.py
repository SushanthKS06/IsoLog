#!/usr/bin/env python3
"""
IsoLog Build Script

Builds standalone executables for different platforms.
"""

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path


def run_command(cmd: list, cwd: Path = None):
    """Run a command and check for errors."""
    print(f"Running: {' '.join(cmd)}")
    result = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"Error: {result.stderr}")
        sys.exit(1)
    print(result.stdout)
    return result


def build_backend():
    """Build backend with PyInstaller."""
    project_root = Path(__file__).parent
    
    print("Building backend executable...")
    
    # Install PyInstaller if needed
    run_command([sys.executable, "-m", "pip", "install", "pyinstaller"])
    
    # Build with spec file
    run_command([
        sys.executable, "-m", "PyInstaller",
        "--clean",
        str(project_root / "isolog.spec"),
    ], cwd=project_root)
    
    print("Backend built successfully!")
    print(f"Output: {project_root / 'dist' / 'isolog'}")


def build_frontend():
    """Build frontend with npm."""
    project_root = Path(__file__).parent
    ui_path = project_root / "ui"
    
    print("Building frontend...")
    
    # Install dependencies
    run_command(["npm", "install"], cwd=ui_path)
    
    # Build
    run_command(["npm", "run", "build"], cwd=ui_path)
    
    print("Frontend built successfully!")
    print(f"Output: {ui_path / 'dist'}")


def build_docker():
    """Build Docker images."""
    project_root = Path(__file__).parent
    docker_path = project_root / "docker"
    
    print("Building Docker images...")
    
    run_command([
        "docker-compose",
        "-f", str(docker_path / "docker-compose.yml"),
        "build",
    ], cwd=project_root)
    
    print("Docker images built successfully!")


def create_portable_package():
    """Create portable package with everything."""
    project_root = Path(__file__).parent
    dist_path = project_root / "dist"
    package_path = dist_path / "isolog-portable"
    
    print("Creating portable package...")
    
    # Clean and create directory
    if package_path.exists():
        shutil.rmtree(package_path)
    package_path.mkdir(parents=True)
    
    # Copy backend executable
    backend_dist = dist_path / "isolog"
    if backend_dist.exists():
        shutil.copytree(backend_dist, package_path / "backend")
    
    # Copy frontend
    frontend_dist = project_root / "ui" / "dist"
    if frontend_dist.exists():
        shutil.copytree(frontend_dist, package_path / "ui")
    
    # Copy config
    shutil.copy2(project_root / "config.yml", package_path)
    
    # Copy rules
    shutil.copytree(project_root / "rules", package_path / "rules")
    
    # Create data directories
    (package_path / "data").mkdir()
    (package_path / "logs").mkdir()
    (package_path / "models").mkdir()
    
    # Create launcher script (Windows)
    launcher_bat = package_path / "start.bat"
    launcher_bat.write_text("""@echo off
echo Starting IsoLog...
cd /d "%~dp0"
start "" "backend\\isolog.exe"
timeout /t 3
start "" "http://localhost:8000"
""")
    
    # Create launcher script (Linux/Mac)
    launcher_sh = package_path / "start.sh"
    launcher_sh.write_text("""#!/bin/bash
cd "$(dirname "$0")"
./backend/isolog &
sleep 3
xdg-open http://localhost:8000 2>/dev/null || open http://localhost:8000
""")
    launcher_sh.chmod(0o755)
    
    # Create README
    readme = package_path / "README.txt"
    readme.write_text("""IsoLog - Portable SIEM for Isolated Networks
=============================================

Quick Start:
- Windows: Double-click start.bat
- Linux/Mac: Run ./start.sh

The web interface will open at http://localhost:8000

Configuration:
- Edit config.yml to customize settings
- Place Sigma rules in rules/sigma_rules/
- ML models go in models/

For updates:
- Place update bundles in the updates/ folder
- Use the Settings page to apply updates

Documentation: https://github.com/your-org/isolog
""")
    
    print(f"Portable package created: {package_path}")
    
    # Create zip archive
    archive_path = dist_path / "isolog-portable.zip"
    shutil.make_archive(
        str(dist_path / "isolog-portable"),
        "zip",
        package_path,
    )
    print(f"Archive created: {archive_path}")


def main():
    parser = argparse.ArgumentParser(description="IsoLog Build Script")
    parser.add_argument(
        "target",
        choices=["backend", "frontend", "docker", "all", "portable"],
        help="Build target",
    )
    
    args = parser.parse_args()
    
    if args.target == "backend":
        build_backend()
    elif args.target == "frontend":
        build_frontend()
    elif args.target == "docker":
        build_docker()
    elif args.target == "all":
        build_backend()
        build_frontend()
        build_docker()
    elif args.target == "portable":
        build_backend()
        build_frontend()
        create_portable_package()


if __name__ == "__main__":
    main()
