#!/bin/bash

# Quick Setup Script for Permission System
# Run this script to set up the database and create initial data

echo "🚀 Setting up Django JWT Auth with Page-Based Permission System..."
echo ""

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Detect Python command

if command -v python3 &>/dev/null; then
    PYTHON_CMD="python3"
elif command -v python &>/dev/null; then
    PYTHON_CMD="python"
else
    echo "✗ Python is not installed. Please install Python 3.6 or higher."
    exit 1
fi

echo "Using Python command: $PYTHON_CMD"
echo ""

# Step 1: Remove old database
echo -e "${YELLOW}Step 1: Cleaning up old database...${NC}"
if [ -f "db.sqlite3" ]; then
    rm db.sqlite3
    echo "✓ Removed old database"
fi

if [ -d "authentication/migrations" ]; then
    rm -rf authentication/migrations
    echo "✓ Removed old migrations"
fi

# Step 2: Create migrations directory
echo -e "\n${YELLOW}Step 2: Creating migrations directory...${NC}"
mkdir -p authentication/migrations
touch authentication/migrations/__init__.py
echo "✓ Migrations directory created"

# Step 3: Generate migrations
echo -e "\n${YELLOW}Step 3: Generating migrations...${NC}"
$PYTHON_CMD manage.py makemigrations authentication
if [ $? -eq 0 ]; then
    echo "✓ Migrations generated successfully"
else
    echo "✗ Migration generation failed"
    exit 1
fi

# Step 4: Apply migrations
echo -e "\n${YELLOW}Step 4: Applying migrations...${NC}"
$PYTHON_CMD manage.py migrate
if [ $? -eq 0 ]; then
    echo "✓ Migrations applied successfully"
else
    echo "✗ Migration application failed"
    exit 1
fi

# Step 5: Seed initial data
echo -e "\n${YELLOW}Step 5: Seeding initial data...${NC}"
$PYTHON_CMD manage.py seed_data
if [ $? -eq 0 ]; then
    echo "✓ Initial data seeded successfully"
else
    echo "✗ Data seeding failed"
    exit 1
fi

# Success message
echo -e "\n${GREEN}✅ Setup completed successfully!${NC}"
echo ""
echo "════════════════════════════════════════════════════"
echo "  Super Admin Credentials"
echo "════════════════════════════════════════════════════"
echo "  Email:    superadmin@lightidea.com"
echo "  Password: SuperAdmin@123"
echo "════════════════════════════════════════════════════"
echo ""
echo "Next steps:"
echo "  1. Start the server:    $PYTHON_CMD manage.py runserver"
echo "  2. Test login:          POST http://localhost:8000/api/auth/login/"
echo "  3. Import Postman:      postman/collections/Page_Permission_System.postman_collection.json"
echo ""
echo "📚 Documentation:"
echo "  - README.md                    - Complete overview"
echo "  - PAGE_PERMISSION_GUIDE.md     - Page-based permission system guide"
echo "  - JWT_TOKEN_GUIDE.md           - JWT authentication guide"
echo ""
