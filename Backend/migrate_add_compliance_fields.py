#!/usr/bin/env python3
"""
Database Migration Script: Add Compliance Fields

Adds cookie_consent_detected and data_leak_safe columns to the scans table.
This migration is required for the cookie consent and data leak detection features.

Usage:
    python3 migrate_add_compliance_fields.py
"""

from database import engine
from sqlalchemy import text

def migrate_add_compliance_fields():
    """Add cookie_consent_detected and data_leak_safe columns to scans table"""

    print("🔄 Starting database migration...")
    print("=" * 60)

    with engine.connect() as conn:
        # Add cookie_consent_detected column
        try:
            conn.execute(text("""
                ALTER TABLE scans
                ADD COLUMN IF NOT EXISTS cookie_consent_detected BOOLEAN DEFAULT FALSE
            """))
            conn.commit()
            print("✅ Added cookie_consent_detected column")
        except Exception as e:
            print(f"⚠️  cookie_consent_detected: {e}")

        # Add data_leak_safe column
        try:
            conn.execute(text("""
                ALTER TABLE scans
                ADD COLUMN IF NOT EXISTS data_leak_safe BOOLEAN DEFAULT TRUE
            """))
            conn.commit()
            print("✅ Added data_leak_safe column")
        except Exception as e:
            print(f"⚠️  data_leak_safe: {e}")

        print("\n" + "=" * 60)
        print("📊 Verifying columns in scans table...")
        print("=" * 60)

        # Verify columns exist
        result = conn.execute(text("""
            SELECT column_name, data_type, column_default
            FROM information_schema.columns
            WHERE table_name = 'scans'
              AND column_name IN ('cookie_consent_detected', 'data_leak_safe')
            ORDER BY column_name
        """))

        rows = result.fetchall()
        if rows:
            for row in rows:
                print(f"  ✓ {row[0]:<30} {row[1]:<15} default: {row[2]}")
            print("\n✅ Migration completed successfully!")
        else:
            print("\n❌ WARNING: Columns not found after migration!")
            print("   Please verify manually in your database.")

if __name__ == "__main__":
    try:
        migrate_add_compliance_fields()
    except Exception as e:
        print(f"\n❌ Migration failed: {e}")
        print("\nPlease check:")
        print("  1. Database connection is working")
        print("  2. DATABASE_URL environment variable is set")
        print("  3. You have permission to alter tables")
        exit(1)
