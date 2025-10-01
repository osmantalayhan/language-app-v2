#!/usr/bin/env python3
"""
Supabase PostgreSQL bağlantı testi
"""

import psycopg2
import os

def test_connection():
    """Supabase bağlantısını test et"""
    
    # Connection string
    database_url = "postgresql://postgres:KXB8aSsm09cJEcFq@db.cmhqcbkjjmajjwqqtaay.supabase.co:5432/postgres"
    
    print("🔗 Supabase PostgreSQL bağlantı testi...")
    print(f"📍 Host: db.cmhqcbkjjmajjwqqtaay.supabase.co")
    print(f"🔌 Port: 5432")
    print(f"🗄️ Database: postgres")
    print("-" * 50)
    
    try:
        # Bağlantı dene
        print("⏳ Bağlantı kuruluyor...")
        conn = psycopg2.connect(database_url)
        
        # Cursor oluştur
        cursor = conn.cursor()
        
        # Test sorgusu
        print("📊 Test sorgusu çalıştırılıyor...")
        cursor.execute("SELECT version();")
        version = cursor.fetchone()
        
        print("✅ Bağlantı başarılı!")
        print(f"🐘 PostgreSQL Version: {version[0]}")
        
        # Mevcut tabloları listele
        cursor.execute("""
            SELECT table_name 
            FROM information_schema.tables 
            WHERE table_schema = 'public'
            ORDER BY table_name;
        """)
        
        tables = cursor.fetchall()
        if tables:
            print(f"📋 Mevcut tablolar ({len(tables)} adet):")
            for table in tables:
                print(f"   - {table[0]}")
        else:
            print("📋 Henüz tablo yok (ilk migration gerekli)")
        
        # Bağlantıyı kapat
        cursor.close()
        conn.close()
        
        print("\n🎉 Test başarılı! Supabase bağlantısı çalışıyor.")
        return True
        
    except psycopg2.OperationalError as e:
        print(f"❌ Bağlantı hatası: {str(e)}")
        
        if "Name or service not known" in str(e):
            print("🌐 DNS sorunu: Host adı çözümlenemiyor")
            print("💡 Çözümler:")
            print("   1. İnternet bağlantınızı kontrol edin")
            print("   2. Firewall/antivirus ayarlarını kontrol edin")
            print("   3. DNS ayarlarınızı kontrol edin (8.8.8.8 deneyin)")
            
        elif "Connection refused" in str(e):
            print("🚫 Bağlantı reddedildi")
            print("💡 Supabase projesi aktif mi kontrol edin")
            
        elif "authentication failed" in str(e):
            print("🔐 Kimlik doğrulama hatası")
            print("💡 Kullanıcı adı/şifre kontrol edin")
            
        return False
        
    except Exception as e:
        print(f"💥 Beklenmeyen hata: {str(e)}")
        return False

if __name__ == '__main__':
    success = test_connection()
    
    if success:
        print("\n🚀 Migration'a hazır!")
        print("   python create_supabase_tables.py komutunu çalıştırabilirsiniz")
    else:
        print("\n⚠️  Önce bağlantı sorununu çözün")
        exit(1)
