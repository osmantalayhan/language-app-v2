#!/usr/bin/env python3
"""
Supabase PostgreSQL için tablo oluşturma scripti
Tüm mevcut tablo yapılarını koruyarak PostgreSQL'e geçiş yapar
"""

import os
from app import app, db, User
from werkzeug.security import generate_password_hash

def create_tables():
    """Tüm tabloları oluştur"""
    with app.app_context():
        try:
            # Tüm tabloları oluştur
            db.create_all()
            print("✅ Tüm tablolar başarıyla oluşturuldu!")
            
            # Tablo listesini yazdır
            tables = db.engine.table_names()
            print(f"📋 Oluşturulan tablolar: {', '.join(tables)}")
            
            # Test kullanıcısı oluştur
            create_test_user()
            
        except Exception as e:
            print(f"❌ Hata: {str(e)}")
            return False
    
    return True

def create_test_user():
    """Test kullanıcısı oluştur"""
    try:
        # Zaten var mı kontrol et
        existing_user = User.query.filter_by(email='admin@test.com').first()
        if existing_user:
            print("⚠️  Test kullanıcısı zaten mevcut")
            return
        
        # Test kullanıcısı oluştur
        test_user = User(
            username='admin',
            email='admin@test.com',
            password_hash=generate_password_hash('admin123'),
            language_level='B2'
        )
        
        db.session.add(test_user)
        db.session.commit()
        
        print("✅ Test kullanıcısı oluşturuldu:")
        print("   📧 Email: admin@test.com")
        print("   🔑 Password: admin123")
        
    except Exception as e:
        print(f"❌ Test kullanıcısı oluşturulamadı: {str(e)}")
        db.session.rollback()

if __name__ == '__main__':
    print("🚀 Supabase PostgreSQL migration başlıyor...")
    
    # DATABASE_URL kontrolü
    database_url = os.getenv('DATABASE_URL', 'postgresql://postgres:KXB8aSsm09cJEcFq@db.cmhqcbkjjmajjwqqtaay.supabase.co:5432/postgres')
    if not database_url:
        print("❌ DATABASE_URL bulunamadı!")
        exit(1)
    
    if 'postgresql' not in database_url:
        print("❌ DATABASE_URL PostgreSQL connection string değil!")
        exit(1)
    
    print(f"🔗 Database: {database_url[:50]}...")
    
    # Migration çalıştır
    if create_tables():
        print("🎉 Migration tamamlandı!")
        print("🔧 Artık uygulamanızı başlatabilirsiniz")
    else:
        print("💥 Migration başarısız!")
        exit(1)
