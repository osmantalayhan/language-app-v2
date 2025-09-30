from flask import Flask, render_template, request, jsonify, redirect, url_for, send_file, flash, session, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import os
import requests
import json
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import re
from urllib.parse import urlparse, urljoin
import asyncio
import edge_tts
import io
from oauthlib.oauth2 import WebApplicationClient
from dotenv import load_dotenv


load_dotenv()

# Allow HTTP for local development
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///words.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'fallback-secret-key')

# Configure Groq API
GROQ_API_KEY = os.getenv('GROQ_API_KEY')
GROQ_API_URL = "https://api.groq.com/openai/v1/chat/completions"

# Hugging Face API configuration
HUGGINGFACE_API_KEY = os.getenv('HUGGINGFACE_API_KEY')
HUGGINGFACE_API_URL = "https://api-inference.huggingface.co/models/facebook/nllb-200-distilled-600M"
headers = {"Authorization": f"Bearer {HUGGINGFACE_API_KEY}"}

# Google OAuth 2.0 Configuration
GOOGLE_CLIENT_ID = os.getenv('GOOGLE_CLIENT_ID')
GOOGLE_CLIENT_SECRET = os.getenv('GOOGLE_CLIENT_SECRET')
GOOGLE_DISCOVERY_URL = "https://accounts.google.com/.well-known/openid-configuration"

# Load environment variables

# OAuth 2.0 client setup
client = WebApplicationClient(GOOGLE_CLIENT_ID)

# Groq API function
def call_groq_api(prompt, max_tokens=500, temperature=0.7):
    """
    Groq API'sine istek gönderir
    """
    try:
        headers = {
            "Authorization": f"Bearer {GROQ_API_KEY}",
            "Content-Type": "application/json"
        }
        
        data = {
            "messages": [
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            "model": "llama-3.3-70b-versatile",  # Güncel model
            "max_tokens": max_tokens,
            "temperature": temperature
        }
        
        response = requests.post(GROQ_API_URL, headers=headers, json=data, timeout=30)
        
        if response.status_code == 200:
            result = response.json()
            return result['choices'][0]['message']['content'].strip()
        else:
            print(f"Groq API error: {response.status_code} - {response.text}")
            return None
            
    except Exception as e:
        print(f"Groq API exception: {str(e)}")
        return None

# Veritabanı yolu
db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'words.db')

# Flask-Login başlatma
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Bu sayfayı görüntülemek için giriş yapmalısınız.'
login_manager.login_message_category = 'info'

db = SQLAlchemy(app)

# Kullanıcı modeli
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(200))  # Made nullable for Google OAuth users
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    words = db.relationship('Word', backref='user', lazy=True)
    google_id = db.Column(db.String(100), unique=True)  # Added for Google OAuth
    profile_pic = db.Column(db.String(200))  # Added for Google profile picture
    failed_login_attempts = db.Column(db.Integer, default=0)  # Failed login attempts counter
    last_failed_login = db.Column(db.DateTime)  # Last failed login timestamp
    language_level = db.Column(db.String(20), default='Beginner')
    level_changed_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=True)  # Son seviye değişiklik tarihi
    daily_goal = db.Column(db.Integer, default=10)
    email_notifications = db.Column(db.String(20), default='Never')
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)  # Son aktivite zamanı
    
    def set_password(self, password):
        """
        Güvenli şifre hash'leme:
        - Werkzeug'un generate_password_hash fonksiyonu zaten güvenli
        - pbkdf2:sha256 algoritması kullanır
        - Varsayılan olarak 260000 iterasyon yapar
        """
        if password:
            self.password_hash = generate_password_hash(
                password,
                method='pbkdf2:sha256:260000'
            )
        
    def check_password(self, password):
        """
        Şifre kontrolü:
        - Başarısız giriş denemelerini kontrol eder
        - Hesap kilitlenmesi için limit uygular
        """
        # Şifre veya hash yoksa
        if not self.password_hash or not password:
            return False
            
        # Hesap kilitlenme kontrolü
        if self.is_account_locked():
            return False
            
        # Şifre kontrolü
        is_valid = check_password_hash(self.password_hash, password)
        
        # Başarısız giriş denemesi
        if not is_valid:
            self.failed_login_attempts += 1
            self.last_failed_login = datetime.utcnow()
            db.session.commit()
        else:
            # Başarılı giriş - sayaçları sıfırla
            self.failed_login_attempts = 0
            self.last_failed_login = None
            db.session.commit()
            
        return is_valid
        
    def is_account_locked(self):
        """
        Hesap kilitlenme kontrolü:
        - 5 başarısız deneme sonrası 15 dakika kilit
        """
        if self.failed_login_attempts >= 5 and self.last_failed_login:
            lock_duration = timedelta(minutes=15)
            if datetime.utcnow() - self.last_failed_login < lock_duration:
                return True
            # Kilit süresi dolduysa sayaçları sıfırla
            self.failed_login_attempts = 0
            self.last_failed_login = None
            db.session.commit()
        return False

    @staticmethod
    def get_or_create_google_user(google_data):
        user = User.query.filter_by(google_id=google_data["sub"]).first()
        if user is None:
            # Check if user exists with same email
            user = User.query.filter_by(email=google_data["email"]).first()
            if user:
                # Update existing user with Google data
                user.google_id = google_data["sub"]
                user.profile_pic = google_data.get("picture")
                # Eğer level_changed_at değeri yoksa set et
                if not user.level_changed_at:
                    user.level_changed_at = datetime.utcnow()
                # Eğer last_seen değeri yoksa set et
                if not user.last_seen:
                    user.last_seen = datetime.utcnow()
            else:
                # Create new user
                username = google_data["email"].split("@")[0]
                # Ensure username is unique
                base_username = username
                counter = 1
                while User.query.filter_by(username=username).first() is not None:
                    username = f"{base_username}{counter}"
                    counter += 1
                
                user = User(
                    username=username,
                    email=google_data["email"],
                    google_id=google_data["sub"],
                    profile_pic=google_data.get("picture"),
                    level_changed_at=datetime.utcnow(),
                    last_seen=datetime.utcnow()
                )
                db.session.add(user)
            db.session.commit()
        return user

@login_manager.user_loader
def load_user(user_id):
    try:
        return User.query.get(int(user_id))
    except Exception as e:
        # If database tables don't exist or user not found, clear session
        print(f"User loading error: {e}")
        session.clear()
        return None

class Word(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    english = db.Column(db.String(100), nullable=False)
    turkish = db.Column(db.String(100), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    mastered = db.Column(db.Boolean, default=False)
    review = db.Column(db.Boolean, default=False)
    example_sentences = db.Column(db.Text, default='')
    level = db.Column(db.String(2), default='')  # A1, A2, B1, B2, C1, C2
    pronunciation = db.Column(db.String(50), default='')
    word_type = db.Column(db.String(20), default='adjective')
    added_by = db.Column(db.String(100), default='John Doe')
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

    def to_dict(self):
        return {
            'id': self.id,
            'english': self.english,
            'turkish': self.turkish,
            'created_at': self.created_at.strftime('%Y-%m-%d %H:%M:%S'),
            'mastered': self.mastered,
            'review': self.review,
            'example_sentences': self.example_sentences.split('|||') if self.example_sentences else [],
            'level': self.level,
            'pronunciation': self.pronunciation,
            'word_type': self.word_type,
            'added_by': self.added_by,
            'user_id': self.user_id
        }

class Activity(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    activity_type = db.Column(db.String(50), nullable=False)  # 'word_added', 'example_added', 'word_mastered', etc.
    word_id = db.Column(db.Integer, db.ForeignKey('word.id'))
    details = db.Column(db.Text)  # JSON string for additional details
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'activity_type': self.activity_type,
            'details': json.loads(self.details) if self.details else {},
            'created_at': self.created_at
        }

class SharedSentence(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sentence = db.Column(db.Text, nullable=False)
    word_id = db.Column(db.Integer, db.ForeignKey('word.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    likes = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    word = db.relationship('Word', backref='shared_sentences')
    user = db.relationship('User', backref='shared_sentences')

    def to_dict(self):
        return {
            'id': self.id,
            'sentence': self.sentence,
            'word_id': self.word_id,
            'user_id': self.user_id,
            'username': self.user.username,
            'likes': self.likes,
            'created_at': self.created_at.strftime('%d %b %Y')
        }

class SentenceLike(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sentence_id = db.Column(db.Integer, db.ForeignKey('shared_sentence.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Unique constraint to prevent duplicate likes
    __table_args__ = (db.UniqueConstraint('sentence_id', 'user_id', name='unique_sentence_like'),)

class SavedWord(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    word_id = db.Column(db.Integer, db.ForeignKey('word.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Unique constraint to prevent duplicate saves
    __table_args__ = (db.UniqueConstraint('user_id', 'word_id', name='unique_saved_word_constraint'),)

class Room(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
    # İlişkiler
    creator = db.relationship('User', backref='created_rooms', foreign_keys=[created_by])
    members = db.relationship('RoomMember', backref='room', cascade='all, delete-orphan')
    
    def to_dict(self):
        # Üye sayısını hesaplayalım
        member_count = RoomMember.query.filter_by(room_id=self.id).count()
        
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'created_at': self.created_at,
            'created_by': self.created_by,
            'creator_name': self.creator.username,
            'member_count': member_count
        }

class RoomMember(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    room_id = db.Column(db.Integer, db.ForeignKey('room.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    joined_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_admin = db.Column(db.Boolean, default=False)
    
    # İlişkiler
    user = db.relationship('User', backref='room_memberships')
    
    # Aynı kullanıcının aynı odaya iki kez üye olmasını engelle
    __table_args__ = (db.UniqueConstraint('room_id', 'user_id', name='unique_room_member'),)

class RoomInvitation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    room_id = db.Column(db.Integer, db.ForeignKey('room.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    invited_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)  # Null for join requests
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20), default='pending')  # pending, accepted, rejected
    request_type = db.Column(db.String(20), default='invitation')  # invitation, join_request
    
    # İlişkiler
    room = db.relationship('Room', backref='invitations')
    user = db.relationship('User', foreign_keys=[user_id], backref='room_invitations')
    inviter = db.relationship('User', foreign_keys=[invited_by], backref='sent_invitations')
    
    # Aynı kullanıcıya aynı oda için birden fazla davet/istek olmasını engelle
    __table_args__ = (db.UniqueConstraint('room_id', 'user_id', name='unique_room_invitation'),)

def translate_to_turkish(english_word, user_id=None):
    try:
        # Kullanıcının seviyesini al
        user_level = "B1"  # Default seviye
        if user_id:
            user = User.query.get(user_id)
            if user and user.language_level:
                user_level = user.language_level
        
        # Groq API kullan
        try:
            prompt = f"""Translate the English word "{english_word}" to Turkish and provide comprehensive analysis.
            The user's English level is {user_level}.

            IMPORTANT: Respond ONLY in English and Turkish. Do NOT use Chinese, Arabic, or any other languages.

            Provide a complete analysis in this exact format:
            Translation: [Turkish translation]
            Level: [CEFR level of this specific word - A1, A2, B1, B2, C1, or C2]
            Sentence1: [SHORT English example sentence (max 12-15 words) matching USER'S level {user_level}]
            Translation1: [Turkish translation of first example]
            Sentence2: [SHORT English example sentence (max 12-15 words) matching USER'S level {user_level}]
            Translation2: [Turkish translation of second example]
            Pronunciation: [IPA phonetic transcription in English format only]
            
            CRITICAL RULES:
            1. Use ONLY English alphabet in example sentences (no Chinese, Arabic, Cyrillic characters)
            2. Example sentences must match the USER'S level ({user_level}), NOT the word's level!
            3. Keep sentences concise and clear
            4. Use standard English vocabulary and grammar
            5. For pronunciation, provide ONLY the IPA (International Phonetic Alphabet) transcription in English format
            6. Do NOT provide Turkish pronunciation guide - only English IPA format like /ˈrʊərəl/ for "rural"
            
            Level guidelines:
            - If user is A1: Use very simple vocabulary and basic grammar in examples
            - If user is A2: Use common vocabulary and simple structures in examples  
            - If user is B1: Use intermediate vocabulary and grammar in examples
            - If user is B2: Use advanced vocabulary and complex grammar in examples
            - If user is C1: Use sophisticated vocabulary and advanced structures in examples
            - If user is C2: Use native-level vocabulary and complex expressions in examples
            
            The word's CEFR level should still be determined independently, but examples must suit the user's level.
            
            PRONUNCIATION EXAMPLES:
            - "rural" should be: /ˈrʊərəl/
            - "predict" should be: /prɪˈdɪkt/
            - "estimate" should be: /ˈestɪmeɪt/"""

            groq_response = call_groq_api(prompt, max_tokens=400, temperature=0.3)
            
            if groq_response:
                lines = [line.strip() for line in groq_response.split('\n') if line.strip()]
                
                translation = ""
                level = "B1"  # default
                examples = []
                pronunciation = ""
                
                # Çince ve diğer Latin olmayan karakterleri temizleyen fonksiyon
                def clean_non_latin(text):
                    import re
                    # Sadece Latin alfabesi, rakamlar, temel noktalama ve Türkçe karakterleri tut
                    # Çince, Arapça, Kiril ve diğer alfabeler kaldırılır
                    cleaned = re.sub(r'[^\x00-\x7F\u00C0-\u017F\u0130\u0131\u011E\u011F\u015E\u015F\u00C7\u00E7\u00D6\u00F6\u00DC\u00FC]', '', text)
                    return cleaned.strip()
                
                for line in lines:
                    if line.startswith("Translation:"):
                        translation = line.split(":", 1)[1].strip()
                    elif line.startswith("Level:"):
                        level = line.split(":", 1)[1].strip()
                    elif line.startswith("Sentence") or line.startswith("Translation"):
                        cleaned_example = clean_non_latin(line.split(":", 1)[1].strip())
                        if cleaned_example and len(cleaned_example) > 3:  # En az 3 karakter olsun
                            examples.append(cleaned_example)
                    elif line.startswith("Pronunciation:"):
                        pronunciation = line.split(":", 1)[1].strip()
                
                if translation and examples:
                    print(f"Groq API translation successful: {translation}")
                    return translation, examples, level, pronunciation
                else:
                    raise Exception("Incomplete Groq response")
                    
        except Exception as e:
            print(f"Groq API failed: {e}")
            
        # Fallback to Hugging Face API for translation only
        try:
            payload = {
                "inputs": english_word,
                "parameters": {
                    "src_lang": "eng_Latn",
                    "tgt_lang": "tur_Latn"
                }
            }

            response = requests.post(HUGGINGFACE_API_URL, headers=headers, json=payload, timeout=10)

            if response.status_code == 200:
                translation = response.json()[0]['translation_text'].strip()
                print(f"Hugging Face translation: {translation}")
            else:
                raise Exception("Hugging Face API error")

        except Exception as e:
            print(f"Hugging Face API failed: {e}")
            # Fallback to simple dictionary
            simple_translations = {
                'hello': 'merhaba',
                'world': 'dünya',
                'book': 'kitap',
                'water': 'su',
                'house': 'ev',
                'car': 'araba',
                'food': 'yemek',
                'time': 'zaman',
                'good': 'iyi',
                'bad': 'kötü',
                'big': 'büyük',
                'small': 'küçük',
                'happy': 'mutlu',
                'sad': 'üzgün',
                'love': 'aşk',
                'friend': 'arkadaş',
                'family': 'aile',
                'work': 'iş',
                'school': 'okul',
                'student': 'öğrenci'
            }
            translation = simple_translations.get(english_word.lower(), f"{english_word} (çeviri bulunamadı)")


        # CEFR seviyesini belirle (basit algoritma)
        word_length = len(english_word)
        if word_length <= 4:
            level = 'A1'
        elif word_length <= 6:
            level = 'A2'
        elif word_length <= 8:
            level = 'B1'
        elif word_length <= 10:
            level = 'B2'
        else:
            level = 'C1'

        # Fallback examples
            examples = [
            f"I learned a new word: {english_word}.",
            f"Yeni bir kelime öğrendim: {translation}.",
            f"Can you use {english_word} in a sentence?",
            f"{translation} kelimesini bir cümlede kullanabilir misin?"
            ]

        print(f"Successfully translated '{english_word}' to '{translation}' (fallback)")
        return translation, examples, level, ""
            
    except Exception as e:
        print(f"Translation error: {str(e)}")
        return None, None, None, None

# Global değişkenler
generated_examples = []
word_extra_info = {'meaning': '', 'level': ''}

# Veritabanını oluştur (sadece eksikse)
with app.app_context():
    # Tabloları kontrol et, eksikse oluştur
    try:
        # Test sorgusu yaparak tablonun var olup olmadığını kontrol et
        User.query.first()
        print("Database tables already exist")
    except Exception:
        # Tablolar yoksa oluştur
        print("Creating database tables...")
    db.create_all()
    
    # Örnek kullanıcı oluştur
    try:
        existing_user = User.query.filter_by(username='test').first()
        if not existing_user:
            test_user = User(username='test', email='test@example.com')
        test_user.set_password('test123')
        db.session.add(test_user)
        db.session.commit()
        print("Test user created")
    except Exception as e:
        print(f"Test user creation error: {e}")
        db.session.rollback()

@app.route('/')
def index():
    if not current_user.is_authenticated:
        return render_template('brand.html')
    update_last_seen()  # Online durumu güncelle
    words = Word.query.filter_by(user_id=current_user.id).order_by(Word.created_at.desc()).all()
    return render_template('index.html', words=words)

@app.route('/dashboard')
@login_required
def dashboard():
    update_last_seen()  # Online durumu güncelle
    # Kullanıcının seviyesi belirlenmemişse onboarding'e yönlendir
    if not current_user.language_level or current_user.language_level == 'Beginner':
        return redirect(url_for('onboarding'))
    
    words = Word.query.filter_by(user_id=current_user.id).order_by(Word.created_at.desc()).all()
    return render_template('index.html', words=words)

@app.route('/words')
@login_required
def words():
    # Burada ileride tüm kayıtlı kelimelere (örneğin genel bir kelime havuzu) erişim sağlanabilir
    # Şimdilik dashboard ile aynı
    words = Word.query.filter_by(user_id=current_user.id).order_by(Word.created_at.desc()).all()
    return render_template('index.html', words=words)

def get_google_provider_cfg():
    try:
        return requests.get(GOOGLE_DISCOVERY_URL).json()
    except:
        return None

@app.route("/login/google")
def google_login():
    # Find out what URL to hit for Google login
    google_provider_cfg = get_google_provider_cfg()
    if not google_provider_cfg:
        return "Error loading Google configuration", 500

    # Get the authorization endpoint
    authorization_endpoint = google_provider_cfg["authorization_endpoint"]

    # Construct the request for Google login and provide scopes
    request_uri = client.prepare_request_uri(
        authorization_endpoint,
        redirect_uri=request.base_url + "/callback",
        scope=["openid", "email", "profile"],
    )
    return redirect(request_uri)

@app.route("/login/google/callback")
def google_callback():
    try:
        # Get authorization code Google sent back
        code = request.args.get("code")
        if not code:
            flash("Error getting authorization from Google", "error")
            return redirect(url_for("login"))

        # Find out what URL to hit to get tokens
        google_provider_cfg = get_google_provider_cfg()
        if not google_provider_cfg:
            flash("Error loading Google configuration", "error")
            return redirect(url_for("login"))

        token_endpoint = google_provider_cfg["token_endpoint"]

        # Prepare and send request to get tokens
        token_url, headers, body = client.prepare_token_request(
            token_endpoint,
            authorization_response=request.url,
            redirect_url=request.base_url,
            code=code,
        )
        
        token_response = requests.post(
            token_url,
            headers=headers,
            data=body,
            auth=(GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET),
        )

        # Parse the tokens
        client.parse_request_body_response(json.dumps(token_response.json()))

        # Get user info from Google
        userinfo_endpoint = google_provider_cfg["userinfo_endpoint"]  # Get the endpoint from config
        uri, headers, body = client.add_token(userinfo_endpoint)
        userinfo_response = requests.get(uri, headers=headers, data=body)

        if userinfo_response.json().get("email_verified"):
            google_data = userinfo_response.json()
            user = User.get_or_create_google_user(google_data)
            login_user(user)
            
            # Yeni kullanıcıysa (seviye belirlenmemişse) onboarding'e yönlendir
            if not user.language_level or user.language_level == 'Beginner':
                flash("Hoş geldiniz! Lütfen İngilizce seviyenizi belirtin.", "info")
                return redirect(url_for("onboarding"))
            else:
                flash("Successfully logged in with Google!", "success")
                return redirect(url_for("dashboard"))
        else:
            flash("Google login failed: Email not verified", "error")
            return redirect(url_for("login"))
            
    except Exception as e:
        print(f"Google callback error: {str(e)}")
        flash("Failed to log in with Google. Please try again.", "error")
        return redirect(url_for("login"))

# Session ayarları
app.permanent_session_lifetime = timedelta(days=7)
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

def is_valid_password(password):
    """
    Şifre karmaşıklığını kontrol eder:
    - En az 8 karakter
    - En az bir büyük harf
    - En az bir küçük harf
    - En az bir rakam
    - En az bir özel karakter
    """
    if len(password) < 8:
        return False
    if not re.search(r"[A-Z]", password):
        return False
    if not re.search(r"[a-z]", password):
        return False
    if not re.search(r"\d", password):
        return False
    if not re.search(r"[ !@#$%&'()*+,-./[\\\]^_`{|}~"+r'"]', password):
        return False
    return True

def is_valid_email(email):
    """Email formatını kontrol eder"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def is_valid_username(username):
    """
    Kullanıcı adı formatını kontrol eder:
    - 3-30 karakter arası
    - Sadece harf, rakam, nokta ve alt çizgi
    """
    pattern = r'^[a-zA-Z0-9._]{3,30}$'
    return re.match(pattern, username) is not None

# Login route'unu güncelle
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
        
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '').strip()
        remember = True if request.form.get('remember') else False
        
        print(f"Login attempt for email: {email}")  # Debug log
        
        # Input validasyonu
        if not email or not password:
            flash('Please fill in all fields.', 'error')
            return redirect(url_for('login'))
            
        if not is_valid_email(email):
            flash('Please enter a valid email address.', 'error')
            return redirect(url_for('login'))
        
        try:
            user = User.query.filter_by(email=email).first()
            print(f"User found: {user is not None}")  # Debug log
            
            # Kullanıcı bulunamadıysa
            if not user:
                flash('Email address not found. Please check your email or sign up.', 'error')
                return redirect(url_for('login'))
                
            # Google hesabı kontrolü
            if user.google_id and not user.password_hash:
                flash('Please use Google login for this account.', 'error')
                return redirect(url_for('login'))
                
            # Hesap kilitli mi kontrol et
            if user.is_account_locked():
                # Kalan süreyi hesapla
                lock_duration = timedelta(minutes=15)
                time_elapsed = datetime.utcnow() - user.last_failed_login
                minutes_remaining = int((lock_duration - time_elapsed).total_seconds() / 60)
                
                return render_template('rate_limit.html', minutes_remaining=minutes_remaining)
                
            # Şifre kontrolü
            valid_password = user.check_password(password)
            print(f"Password check result: {valid_password}")  # Debug log
            
            if not valid_password:
                flash('Invalid password. Please try again.', 'error')
                return redirect(url_for('login'))
                
            # Giriş başarılı - Sayaçları sıfırla
            user.failed_login_attempts = 0
            user.last_failed_login = None
            db.session.commit()

            # Session güvenliği
            session.permanent = True
            login_user(user, remember=remember)
            flash('Successfully logged in!', 'success')
            
            # Session yenileme (Session Fixation koruması)
            session.regenerate()
            
            print("Login successful, redirecting to dashboard")  # Debug log
            
            # Güvenli yönlendirme
            next_page = request.args.get('next')
            if next_page and not is_safe_url(next_page):
                return abort(400)
            return redirect(next_page if next_page else url_for('dashboard'))
            
        except Exception as e:
            print(f"Login error: {str(e)}")  # Debug log
            flash('An error occurred during login. Please try again.', 'error')
            return redirect(url_for('login'))
        
    return render_template('login.html')

# Register route'unu güncelle
@app.route('/register', methods=['GET', 'POST'])
# @limiter.limit("3 per minute") # Rate limiting DISABLED
def register():
    if request.method == 'GET':
        return render_template('register.html')
    
    if request.method == 'POST':
        print("Register POST request received") # Debug log
        try:
            username = request.form.get('username')
            email = request.form.get('email')
            password = request.form.get('password')
            confirm_password = request.form.get('confirm_password')
            
            print(f"Form data received - Username: {username}, Email: {email}") # Debug log
            
            # Input validation
            if not username or not email or not password or not confirm_password:
                flash('All fields are required', 'error')
                return redirect(url_for('register'))
            
            print("Input validation passed") # Debug log
            
            # Username validation
            if not is_valid_username(username):
                flash('Username must be between 3-30 characters and contain only letters, numbers, dots and underscores', 'error')
                return redirect(url_for('register'))
            
            # Email validation
            if not is_valid_email(email):
                flash('Please enter a valid email address', 'error')
                return redirect(url_for('register'))
            
            # Password validation
            if not is_valid_password(password):
                flash('Password must be at least 8 characters long and contain uppercase, lowercase, number and special character', 'error')
                return redirect(url_for('register'))
            
            # Password match validation
            if password != confirm_password:
                flash('Passwords do not match', 'error')
                return redirect(url_for('register'))
            
            print("All validations passed") # Debug log
            
            # Check if user already exists
            if User.query.filter_by(username=username).first():
                flash('Username already exists', 'error')
                return redirect(url_for('register'))
            
            if User.query.filter_by(email=email).first():
                flash('Email already registered', 'error')
                return redirect(url_for('register'))
            
            print("User existence check passed") # Debug log
            
            # Create new user
            user = User(username=username, email=email)
            user.set_password(password)
            
            try:
                db.session.add(user)
                db.session.commit()
                print("User successfully created") # Debug log
                
                # Kullanıcıyı otomatik login yap ve onboarding'e yönlendir
                login_user(user, remember=True)
                return redirect(url_for('onboarding'))
            except Exception as e:
                print(f"Database error: {str(e)}") # Debug log
                db.session.rollback()
                flash('An error occurred during registration. Please try again.', 'error')
                return redirect(url_for('register'))
                
        except Exception as e:
            print(f"Unexpected error: {str(e)}") # Debug log
            flash('An unexpected error occurred. Please try again.', 'error')
            return redirect(url_for('register'))
    
    return render_template('register.html')

def is_safe_url(target):
    """Güvenli URL kontrolü"""
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ('http', 'https') and ref_url.netloc == test_url.netloc

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/onboarding')
@login_required
def onboarding():
    # Eğer kullanıcının seviyesi zaten belirlenmişse dashboard'a yönlendir
    current_level = current_user.language_level
    if current_level and current_level in ['A1', 'A2', 'B1', 'B2', 'C1', 'C2']:
        return redirect(url_for('dashboard'))
    return render_template('onboarding.html')

@app.route('/migrate_levels')
@login_required 
def migrate_levels():
    """Eski format seviyelerini yeni formata çevir"""
    try:
        # Tüm kullanıcıları güncelle
        users = User.query.all()
        updated_count = 0
        
        for user in users:
            old_level = user.language_level
            if old_level == 'Beginner':
                user.language_level = 'A2'
                updated_count += 1
            elif old_level == 'Intermediate':
                user.language_level = 'B1'
                updated_count += 1
            elif old_level == 'Advanced':
                user.language_level = 'C1'
                updated_count += 1
        
        db.session.commit()
        return f"Migration tamamlandı. {updated_count} kullanıcı güncellendi."
    except Exception as e:
        return f"Migration hatası: {str(e)}"

@app.route('/set_language_level', methods=['POST'])
@login_required
def set_language_level():
    try:
        data = request.get_json()
        language_level = data.get('language_level')
        
        if not language_level or language_level not in ['A1', 'A2', 'B1', 'B2', 'C1', 'C2']:
            return jsonify({'error': 'Geçersiz seviye'}), 400
        
        current_user.language_level = language_level
        db.session.commit()
        
        return jsonify({'success': True}), 200
    except Exception as e:
        print(f"Error setting language level: {e}")
        return jsonify({'error': 'Bir hata oluştu'}), 500

def calculate_accuracy_rate(user_id):
    # Son 30 gündeki doğru ve yanlış cevapları hesapla
    total_words = Word.query.filter_by(user_id=user_id).count()
    mastered_words = Word.query.filter_by(user_id=user_id, mastered=True).count()
    
    if total_words == 0:
        return 0
    
    return int((mastered_words / total_words) * 100)

def calculate_daily_average(user_id):
    # Son 30 gündeki günlük ortalama kelime sayısı
    thirty_days_ago = datetime.utcnow() - timedelta(days=30)
    words = Word.query.filter(
        Word.user_id == user_id,
        Word.created_at >= thirty_days_ago
    ).all()
    
    if not words:
        return 0
    
    # Günlere göre kelime sayılarını grupla
    daily_counts = {}
    for word in words:
        day = word.created_at.date()
        daily_counts[day] = daily_counts.get(day, 0) + 1
    
    if not daily_counts:
        return 0
        
    # Aktif günlerin ortalamasını al
    return int(sum(daily_counts.values()) / len(daily_counts))

def calculate_active_days(user_id):
    # Son 30 gündeki aktif gün sayısı
    thirty_days_ago = datetime.utcnow() - timedelta(days=30)
    words = Word.query.filter(
        Word.user_id == user_id,
        Word.created_at >= thirty_days_ago
    ).all()
    
    # Benzersiz günleri say
    active_days = set()
    for word in words:
        active_days.add(word.created_at.date())
    
    return len(active_days)

@app.route('/statistics')
@login_required
def statistics():
    # Kelime istatistikleri
    total_words = Word.query.filter_by(user_id=current_user.id).count()
    mastered_words = Word.query.filter_by(user_id=current_user.id, mastered=True).count()
    review_words = Word.query.filter_by(user_id=current_user.id, review=True).count()
    
    # Seviyeye göre kelime dağılımı
    a1_words = Word.query.filter_by(user_id=current_user.id, level='A1').count()
    a2_words = Word.query.filter_by(user_id=current_user.id, level='A2').count()
    b1_words = Word.query.filter_by(user_id=current_user.id, level='B1').count()
    b2_words = Word.query.filter_by(user_id=current_user.id, level='B2').count()
    c1_words = Word.query.filter_by(user_id=current_user.id, level='C1').count()
    c2_words = Word.query.filter_by(user_id=current_user.id, level='C2').count()
    
    # Günlük, haftalık, aylık aktivite
    today = datetime.utcnow().date()
    week_ago = today - timedelta(days=7)
    month_ago = today - timedelta(days=30)
    
    words_today = Word.query.filter(
        Word.user_id == current_user.id,
        Word.created_at >= today
    ).count()
    
    words_week = Word.query.filter(
        Word.user_id == current_user.id,
        Word.created_at >= week_ago
    ).count()
    
    words_month = Word.query.filter(
        Word.user_id == current_user.id,
        Word.created_at >= month_ago
    ).count()
    
    # Öğrenme hızı (son 30 gündeki günlük ortalama)
    learning_rate = calculate_daily_average(current_user.id)
    
    # Doğruluk oranı
    accuracy_rate = calculate_accuracy_rate(current_user.id)
    
    # Aktif günler ve streak
    active_days = calculate_active_days(current_user.id)
    current_streak = calculate_streak(current_user.id)
    
    # Son 10 kelime
    recent_words = Word.query.filter_by(user_id=current_user.id).order_by(Word.created_at.desc()).limit(10).all()
    
    # Liderlik istatistikleri hesapla
    leadership_stats = calculate_leadership_stats(current_user.id)
    
    stats = {
        'total_words': total_words,
        'mastered_words': mastered_words,
        'review_words': review_words,
        'level_distribution': {
            'A1': a1_words,
            'A2': a2_words,
            'B1': b1_words,
            'B2': b2_words,
            'C1': c1_words,
            'C2': c2_words,
        },
        'activity': {
            'today': words_today,
            'week': words_week,
            'month': words_month,
        },
        'learning_rate': learning_rate,
        'accuracy_rate': accuracy_rate,
        'active_days': active_days,
        'current_streak': current_streak,
        'leadership': leadership_stats
    }
    
    return render_template('statistics.html', stats=stats, recent_words=recent_words)

@app.route('/leaderboard')
@login_required
def leaderboard():
    update_last_seen()  # Online durumu güncelle
    # Gelişmiş leaderboard verilerini al
    data = get_enhanced_leaderboard_data(current_user.id)
    
    return render_template('leaderboard.html', **data)

@app.route('/profile')
@login_required
def profile():
    # Temel istatistikler
    stats = {
        'total_words': Word.query.filter_by(user_id=current_user.id).count(),
        'mastered_words': Word.query.filter_by(user_id=current_user.id, mastered=True).count(),
        'learning_streak': calculate_streak(current_user.id),
        'accuracy_rate': calculate_accuracy_rate(current_user.id),
        'daily_average': calculate_daily_average(current_user.id),
        'active_days': calculate_active_days(current_user.id)
    }

    # Son aktiviteleri al
    recent_activities = []
    activities = Activity.query.filter_by(user_id=current_user.id).order_by(Activity.created_at.desc()).limit(50).all()
    
    for activity in activities:
        activity_data = {
            'date': activity.created_at,
            'title': '',
            'details': json.loads(activity.details) if activity.details else {},
            'activity_type': activity.activity_type,
            'icon': 'plus'  # Varsayılan ikon
        }

        # Word nesnesini al (eğer word_id varsa)
        word = None
        if activity.word_id:
            word = Word.query.get(activity.word_id)

        # Aktivite tipine göre başlık ve ikon ayarla
        if activity.activity_type == 'word_added' and word:
            activity_data['title'] = f"Added '{word.english}' to vocabulary"
            activity_data['icon'] = 'plus'
            activity_data['details']['word'] = word.english
            activity_data['details']['translation'] = word.turkish
            activity_data['details']['level'] = word.level
        elif activity.activity_type == 'example_added' and word:
            activity_data['title'] = f"Added example for '{word.english}'"
            activity_data['icon'] = 'edit'
            activity_data['details']['word'] = word.english
            activity_data['details']['level'] = word.level
        elif activity.activity_type == 'word_mastered' and word:
            activity_data['title'] = f"Mastered the word '{word.english}'"
            activity_data['icon'] = 'check'
            activity_data['details']['word'] = word.english
            activity_data['details']['level'] = word.level
        elif activity.activity_type == 'sentence_exercise' and word:
            activity_data['title'] = f"Practiced '{word.english}' in a sentence"
            activity_data['icon'] = 'edit'
            activity_data['details']['word'] = word.english
            activity_data['details']['level'] = word.level
            activity_data['details']['sentence'] = activity_data['details'].get('sentence', '')
        elif activity.activity_type == 'sentence_shared' and word:
            activity_data['title'] = f"Shared a sentence with '{word.english}'"
            activity_data['icon'] = 'edit'
            activity_data['details']['word'] = word.english
            activity_data['details']['level'] = word.level if word else ''
            activity_data['details']['sentence'] = activity_data['details'].get('sentence', '')
        elif activity.activity_type == 'daily_goal':
            activity_data['title'] = "Reached daily word goal!"
            activity_data['icon'] = 'star'
        elif activity.activity_type == 'streak_milestone':
            activity_data['title'] = f"Achieved {activity_data['details'].get('days', 0)} day streak!"
            activity_data['icon'] = 'fire'

        recent_activities.append(activity_data)

    return render_template('profile.html', 
                         user=current_user, 
                         stats=stats,
                         recent_activities=recent_activities)

def get_enhanced_leaderboard_data(current_user_id):
    """Gelişmiş leaderboard verilerini hesapla"""
    thirty_days_ago = datetime.utcnow() - timedelta(days=30)
    seven_days_ago = datetime.utcnow() - timedelta(days=7)
    
    # Aktif kullanıcıları al
    active_users = db.session.query(User).join(Word).filter(
        Word.created_at >= thirty_days_ago
    ).distinct().all()
    
    users_stats = []
    current_user_data = None
    
    for user in active_users:
        # Temel istatistikler
        total_words = Word.query.filter_by(user_id=user.id).count()
        words_this_month = Word.query.filter(
            Word.user_id == user.id,
            Word.created_at >= thirty_days_ago
        ).count()
        
        # Son 7 günlük aktivite
        words_this_week = Word.query.filter(
            Word.user_id == user.id,
            Word.created_at >= seven_days_ago
        ).count()
        
        
        # Diğer metrikler
        current_streak = calculate_streak(user.id)
        accuracy_rate = calculate_accuracy_rate(user.id)
        daily_average = calculate_daily_average(user.id)
        
        # Toplam puan
        total_score = total_words * 10 + current_streak * 20 + accuracy_rate * 5
        
        user_data = {
            'user': user,
            'total_words': total_words,
            'words_this_month': words_this_month,
            'words_this_week': words_this_week,
            'daily_average': daily_average,
            'current_streak': current_streak,
            'accuracy_rate': accuracy_rate,
            'total_score': total_score
        }
        
        users_stats.append(user_data)
        
        if user.id == current_user_id:
            current_user_data = user_data
    
    # Sıralamaları hesapla
    users_stats.sort(key=lambda x: x['total_score'], reverse=True)
    for i, user_stat in enumerate(users_stats, 1):
        user_stat['rank'] = i
    
    # En aktif kullanıcılar (son 7 gün)
    most_active_users = sorted(users_stats, key=lambda x: x['words_this_week'], reverse=True)[:10]
    
    
    # Current user karşılaştırma verisi
    comparison_data = None
    if current_user_data:
        # Benzer seviyedeki kullanıcıları bul (±5 sıra)
        current_rank = current_user_data['rank']
        comparison_users = []
        
        for user_stat in users_stats:
            if abs(user_stat['rank'] - current_rank) <= 5 and user_stat['user'].id != current_user_id:
                comparison_users.append(user_stat)
        
        comparison_data = {
            'current_user': current_user_data,
            'nearby_users': comparison_users[:5],
            'avg_score': sum(u['total_score'] for u in comparison_users) / len(comparison_users) if comparison_users else 0,
            'avg_words': sum(u['total_words'] for u in comparison_users) / len(comparison_users) if comparison_users else 0,
            'avg_streak': sum(u['current_streak'] for u in comparison_users) / len(comparison_users) if comparison_users else 0
        }
    
    return {
        'leaderboard': users_stats[:50],  # Top 50
        'current_user_stats': current_user_data,
        'most_active': most_active_users,
        'comparison': comparison_data
    }

def calculate_leadership_stats(user_id):
    """Kullanıcının liderlik istatistiklerini hesapla"""
    thirty_days_ago = datetime.utcnow() - timedelta(days=30)
    seven_days_ago = datetime.utcnow() - timedelta(days=7)
    
    # Tüm aktif kullanıcıları al
    all_users = db.session.query(User).join(Word).filter(
        Word.created_at >= thirty_days_ago
    ).distinct().all()
    
    user_rankings = []
    current_user_data = None
    
    for user in all_users:
        # Her kullanıcı için metrikleri hesapla
        daily_avg = calculate_daily_average(user.id)
        streak = calculate_streak(user.id)
        accuracy = calculate_accuracy_rate(user.id)
        
        user_data = {
            'user_id': user.id,
            'username': user.username,
            'daily_average': daily_avg,
            'streak': streak,
            'accuracy': accuracy
        }
        
        user_rankings.append(user_data)
        
        if user.id == user_id:
            current_user_data = user_data
    
    # Sıralamaları hesapla
    fastest_learners = sorted(user_rankings, key=lambda x: x['daily_average'], reverse=True)
    most_consistent = sorted(user_rankings, key=lambda x: x['streak'], reverse=True)
    most_accurate = sorted(user_rankings, key=lambda x: x['accuracy'], reverse=True)
    
    # Current user'ın pozisyonlarını bul
    fastest_rank = next((i+1 for i, u in enumerate(fastest_learners) if u['user_id'] == user_id), None)
    consistent_rank = next((i+1 for i, u in enumerate(most_consistent) if u['user_id'] == user_id), None)
    accurate_rank = next((i+1 for i, u in enumerate(most_accurate) if u['user_id'] == user_id), None)
    
    # Son 7 günlük gelişim hesapla (basit simülasyon)
    progress_data = []
    for i in range(7):
        day = datetime.utcnow() - timedelta(days=6-i)
        # Basit bir progress simülasyonu (gerçekte daha karmaşık olabilir)
        base_rank = fastest_rank if fastest_rank else 50
        variation = (i - 3) * 2  # -6 ile +6 arası değişim
        daily_rank = max(1, min(base_rank + variation, 100))
        progress_data.append({
            'date': day.strftime('%d.%m'),
            'rank': daily_rank
        })
    
    return {
        'rankings': {
            'fastest_rank': fastest_rank,
            'consistent_rank': consistent_rank,
            'accurate_rank': accurate_rank
        },
        'leaders': {
            'fastest': fastest_learners[:3],
            'consistent': most_consistent[:3],
            'accurate': most_accurate[:3]
        },
        'progress': progress_data,
        'total_users': len(all_users)
    }

def calculate_streak(user_id):
    # Basit bir streak hesaplama fonksiyonu
    today = datetime.utcnow().date()
    streak = 0
    
    # Son 30 günlük kelimeleri al
    words = Word.query.filter_by(user_id=user_id)\
        .filter(Word.created_at >= today - timedelta(days=30))\
        .order_by(Word.created_at.desc())\
        .all()
    
    if not words:
        return 0
        
    # Günlük aktiviteleri grupla
    daily_activities = {}
    for word in words:
        day = word.created_at.date()
        daily_activities[day] = daily_activities.get(day, 0) + 1
    
    # Streak hesapla
    check_date = today
    while check_date in daily_activities:
        streak += 1
        check_date = check_date - timedelta(days=1)
    
    return streak

@app.route('/add_word', methods=['POST'])
@login_required
def add_word():
    english = request.form.get('english', '').strip()
    print(f"Attempting to add word: {english}")  # Debug log
    
    if not english:
        print("Empty word submitted")  # Debug log
        return jsonify(success=False, error="Please enter a word"), 400
        
    try:
        # Kullanıcının kendi kelime listesinde bu kelime var mı kontrol et
        existing_word = Word.query.filter(Word.english.ilike(english), Word.user_id==current_user.id).first()
            
        if existing_word:
            print(f"Word '{english}' already exists for user {current_user.id}")  # Debug log
            return jsonify(success=False, error="This word already exists"), 400
        
        print(f"Calling translate_to_turkish for word: {english}")  # Debug log
        turkish, examples, level, pronunciation = translate_to_turkish(english, current_user.id)
        
        if not turkish:
            print(f"Translation failed for word: {english}")  # Debug log
            return jsonify(success=False, error="Translation failed. Please try again."), 500
        
        print(f"Successfully translated '{english}' to '{turkish}'")  # Debug log
        
        new_word = Word(
            english=english.lower(),
            turkish=turkish,
            example_sentences='|||'.join(examples) if examples else '',
            level=level or 'B1',  # Default to B1 if no level returned
            pronunciation=pronunciation or '',
            word_type='',
            added_by=current_user.username,
            user_id=current_user.id
        )
        
        db.session.add(new_word)
        db.session.flush()  # Yeni kelime ID'sini almak için flush yapıyoruz
        
        print(f"Added new word to database: {new_word.english}")  # Debug log
        
        # Kelime ekleme aktivitesi
        activity = Activity(
            user_id=current_user.id,
            activity_type='word_added',
            word_id=new_word.id,
            details=json.dumps({
                'word': english.lower(),
                'turkish': turkish,
                'level': level or 'B1',
                'translation': turkish
            })
        )
        db.session.add(activity)
        
        # Günlük hedef kontrolü
        today_words = Word.query.filter(
            Word.user_id == current_user.id,
            Word.created_at >= datetime.utcnow().date()
        ).count()
        
        if today_words in [10, 25, 50, 100]:  # Günlük hedef sayıları
            milestone_activity = Activity(
                user_id=current_user.id,
                activity_type='daily_goal',
                details=json.dumps({
                    'words_count': today_words
                })
            )
            db.session.add(milestone_activity)
        
        db.session.commit()
        print(f"Successfully completed adding word: {english}")  # Debug log
        return jsonify(success=True, word=new_word.to_dict())
        
    except Exception as e:
        db.session.rollback()
        error_msg = str(e)
        print(f"Add word error for '{english}': {error_msg}")  # Debug log
        
        if "API key not valid" in error_msg:
            return jsonify(success=False, error="Service temporarily unavailable. Please try again later."), 503
        elif "Failed to initialize any model" in error_msg:
            return jsonify(success=False, error="Translation service is currently unavailable. Please try again later."), 503
        else:
            return jsonify(success=False, error="Failed to add word. Please try again."), 500

@app.route('/get_word/<int:word_id>')
def get_word(word_id):
    word = Word.query.get_or_404(word_id)
    
    # Check if user can access this word
    if current_user.is_authenticated and word.user_id != current_user.id:
        # Check if user is in the same room as the word owner
        user_rooms = [rm.room_id for rm in RoomMember.query.filter_by(user_id=current_user.id).all()]
        word_owner_rooms = [rm.room_id for rm in RoomMember.query.filter_by(user_id=word.user_id).all()]
        common_rooms = set(user_rooms) & set(word_owner_rooms)
        
        if not common_rooms:
            abort(404)  # User cannot access this word
    
    return jsonify(word.to_dict())

@app.route('/mark_mastered/<int:word_id>', methods=['POST'])
@login_required
def mark_mastered(word_id):
    try:
        word = Word.query.filter_by(id=word_id, user_id=current_user.id).first_or_404()
        word.mastered = True
        
        # Add activity record for word mastered
        activity = Activity(
            user_id=current_user.id,
            activity_type='word_mastered',
            word_id=word.id,
            details=json.dumps({
                'word': word.english,
                'level': word.level
            })
        )
        db.session.add(activity)
        
        db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)})

@app.route('/mark_review/<int:word_id>', methods=['POST'])
def mark_review(word_id):
    if current_user.is_authenticated:
        word = Word.query.filter_by(id=word_id, user_id=current_user.id).first_or_404()
    else:
        word = Word.query.filter_by(id=word_id, user_id=None).first_or_404()
    word.review = True
    word.mastered = False
    db.session.commit()
    return jsonify(success=True)

@app.route('/get_stats')
def get_stats():
    if current_user.is_authenticated:
        total_words = Word.query.filter_by(user_id=current_user.id).count()
        mastered_words = Word.query.filter_by(user_id=current_user.id, mastered=True).count()
        review_words = Word.query.filter_by(user_id=current_user.id, review=True).count()
    else:
        total_words = Word.query.filter_by(user_id=None).count()
        mastered_words = Word.query.filter_by(user_id=None, mastered=True).count()
        review_words = Word.query.filter_by(user_id=None, review=True).count()
    
    return jsonify({
        'total': total_words,
        'mastered': mastered_words,
        'review': review_words
    })

@app.route('/delete_word/<int:word_id>', methods=['POST'])
@login_required
def delete_word(word_id):
    try:
        word = Word.query.filter_by(id=word_id, user_id=current_user.id).first_or_404()
        
        # Delete related shared sentences
        SharedSentence.query.filter_by(word_id=word_id).delete()
        
        # Delete related activities
        Activity.query.filter_by(word_id=word_id).delete()
        
        # Delete the word
        db.session.delete(word)
        db.session.commit()
        
        return jsonify(success=True)
    except Exception as e:
        db.session.rollback()
        print(f"Error deleting word: {str(e)}")
        return jsonify(success=False, error=str(e)), 500

@app.route('/word/<int:word_id>')
@login_required
def word_detail(word_id):
    # Get the word from the database
    word = Word.query.get_or_404(word_id)
    
    # Check if user can access this word
    # Either the word belongs to the user OR the user is in the same room with the word owner
    if word.user_id != current_user.id:
        # Check if both users are in any common room
        user_rooms = [rm.room_id for rm in RoomMember.query.filter_by(user_id=current_user.id).all()]
        word_owner_rooms = [rm.room_id for rm in RoomMember.query.filter_by(user_id=word.user_id).all()]
        common_rooms = set(user_rooms) & set(word_owner_rooms)
        
        if not common_rooms:
            abort(404)  # User cannot access this word
    
    # Get the user who added this word
    added_by_user = User.query.get(word.user_id) if word.user_id else None
    
    # Get related words (same level, accessible to user)
    if word.user_id == current_user.id:
        # If it's user's own word, show related words from same user
        related_words = Word.query.filter(
            Word.user_id == current_user.id,
            Word.level == word.level,
            Word.id != word.id
        ).limit(6).all()
    else:
        # If it's from room mate, show related words from same room members
        user_rooms = [rm.room_id for rm in RoomMember.query.filter_by(user_id=current_user.id).all()]
        room_member_ids = [rm.user_id for rm in RoomMember.query.filter(RoomMember.room_id.in_(user_rooms)).all()]
        
        related_words = Word.query.filter(
            Word.user_id.in_(room_member_ids),
            Word.level == word.level,
            Word.id != word.id
        ).limit(6).all()
    
    # Format the date
    formatted_date = word.created_at.strftime('%B %d, %Y')
    
    # Get level color
    level_colors = {
        'A1': 'bg-blue-500/20 text-blue-400',
        'A2': 'bg-green-500/20 text-green-400',
        'B1': 'bg-yellow-500/20 text-yellow-400',
        'B2': 'bg-orange-500/20 text-orange-400',
        'C1': 'bg-purple-500/20 text-purple-400',
        'C2': 'bg-red-500/20 text-red-400'
    }
    level_color = level_colors.get(word.level, 'bg-gray-500/20 text-gray-400')
    
    # Load example sentences server-side to avoid loading state
    examples = []
    if word.example_sentences:
        stored_examples = word.example_sentences.split('|||')
        if len(stored_examples) >= 4:
            examples = stored_examples
    
    # If no examples exist, use fallback
    if not examples:
        examples = [
            f"I use the word '{word.english}' in my daily conversations.",
            f"'{word.turkish}' kelimesini günlük konuşmalarımda kullanırım.",
            f"Learning '{word.english}' helps improve my English vocabulary.",
            f"'{word.turkish}' kelimesini öğrenmek İngilizce kelime dağarcığımı geliştirir."
        ]

    return render_template('word_detail.html',
        word=word,
        related_words=related_words,
        formatted_date=formatted_date,
        level_color=level_color,
        examples=examples,
        added_by_user=added_by_user)

@app.route('/load_examples/<int:word_id>')
def load_examples(word_id):
    try:
        word = Word.query.get_or_404(word_id)
        
        # Check if user can access this word (same logic as word_detail)
        if current_user.is_authenticated and word.user_id != current_user.id:
            # Check if user is in the same room as the word owner
            user_rooms = [rm.room_id for rm in RoomMember.query.filter_by(user_id=current_user.id).all()]
            word_owner_rooms = [rm.room_id for rm in RoomMember.query.filter_by(user_id=word.user_id).all()]
            common_rooms = set(user_rooms) & set(word_owner_rooms)
            
            if not common_rooms:
                return jsonify(success=False, error="Bu kelimeye erişim yetkiniz yok"), 403
        
        # Force regenerate parametresi (isteğe göre yeniden üret)
        force_regenerate = request.args.get('force_regenerate', 'false').lower() == 'true'
        
        # Eğer yeniden üretim isteniyorsa, seviye değişim limiti kontrol et
        if force_regenerate and current_user.is_authenticated:
            # Kullanıcının level_changed_at değeri varsa kontrol et
            if current_user.level_changed_at:
                # Bu kelime için son seviye değişiminden sonra regeneration yapılmış mı?
                last_regeneration = Activity.query.filter(
                    Activity.user_id == current_user.id,
                    Activity.activity_type == 'example_regenerated',
                    Activity.word_id == word_id,
                    Activity.created_at > current_user.level_changed_at
                ).first()
                
                if last_regeneration:
                    return jsonify(success=False, error="Bu kelime için seviye değişiminden sonra zaten örnek cümle yenilendi."), 429
        
        # Eğer kelime detay sayfası açıldığında burada örnek cümle yoksa veya yeniden üretim isteniyorsa
        if not word.example_sentences or len(word.example_sentences.split('|||')) < 4 or force_regenerate:
            examples = []
            
            # Kullanıcının seviyesini al
            user_level = "B1"  # Default seviye
            if current_user.is_authenticated and current_user.language_level:
                user_level = current_user.language_level
            
            # Groq API kullan
            try:
                # Kullanıcının seviyesine göre örnek cümleler oluştur
                prompt = f'''Create exactly 2 natural example sentences for the English word "{word.english}" and their Turkish translations.
                These should be REALISTIC, everyday examples reflecting how native speakers naturally use this word in casual conversation.
                IMPORTANT: 
                - Sentence complexity and vocabulary should match {user_level} CEFR level exactly
                - Keep sentences reasonably SHORT (maximum 12-15 words each)
                - Avoid overly long or complex sentences even for C1/C2 levels
                    
                    For {user_level} level:
                    - A1: Very simple vocabulary, basic structures, present tense (5-8 words)
                    - A2: Common vocabulary, simple past/future, basic adjectives (6-10 words)
                    - B1: Intermediate vocabulary, various tenses, some complexity (8-12 words)
                    - B2: Advanced vocabulary, complex grammar, but concise (10-14 words)
                    - C1: Sophisticated vocabulary, advanced grammar, but SHORT (10-15 words)
                    - C2: Native-level vocabulary, nuanced expressions, but CONCISE (10-15 words)
                    
                DON'T use artificial sentences like "The word '{word.english}' is useful."
                Instead, show real-life contexts where someone would naturally use this word.
                
                Format your response exactly like this without any other text:
                    Sentence1: [natural English example matching {user_level} level]
                Translation1: [accurate Turkish translation of first example]
                    Sentence2: [different natural English example matching {user_level} level]
                Translation2: [accurate Turkish translation of second example]'''

                groq_response = call_groq_api(prompt, max_tokens=300, temperature=0.7)

                if groq_response:
                    # API yanıtını satırlara ayırıp analiz edelim
                    lines = [line.strip() for line in groq_response.split('\n') if line.strip()]
                
                    # Satırları dolaş ve cümleleri çıkar
                    for line in lines:
                        if line.startswith("Sentence1:"):
                            examples.append(line.replace("Sentence1:", "").strip())
                        elif line.startswith("Translation1:"):
                            examples.append(line.replace("Translation1:", "").strip())
                        elif line.startswith("Sentence2:"):
                            examples.append(line.replace("Sentence2:", "").strip())
                        elif line.startswith("Translation2:"):
                            examples.append(line.replace("Translation2:", "").strip())
            except Exception as e:
                print(f"Groq API example generation failed: {e}")


            # Fallback examples veya AI başarısızsa
            if len(examples) < 4:
                examples = [
                    f"I find it hard to work with James because he's so {word.english}.",
                    f"James'in bu kadar {word.turkish} olması nedeniyle onunla çalışmakta zorlanıyorum.",
                    f"Children tend to become {word.english} when they're tired after a long day.",
                    f"Çocuklar uzun bir günün ardından yorgun olduklarında {word.turkish} olmaya meyilli olurlar."
                ]

            # Örnekler oluşturulduktan sonra aktivite ekle
            if force_regenerate:
                # Yeniden üretim aktivitesi
                activity = Activity(
                    user_id=current_user.id,
                    activity_type='example_regenerated',
                    word_id=word.id,
                    details=json.dumps({
                        'examples_count': len(examples) // 2,
                        'user_level': user_level,
                        'word': word.english
                    })
                )
            else:
                # İlk kez üretim aktivitesi
                activity = Activity(
                    user_id=current_user.id,
                    activity_type='example_added',
                    word_id=word.id,
                    details=json.dumps({
                        'examples_count': len(examples) // 2,  # İngilizce ve Türkçe çiftler olduğu için 2'ye böl
                        'level': word.level
                    })
                )
            db.session.add(activity)

            # Örnekleri veritabanına kaydet
            word.example_sentences = '|||'.join(examples)
            db.session.commit()
            return jsonify(success=True, examples=examples)
        else:
            # Eğer zaten örnek cümleler varsa onları döndür
            examples = word.example_sentences.split('|||')
            return jsonify(success=True, examples=examples)

    except Exception as e:
        print(f"Load examples error: {str(e)}")
        # Hata durumunda bile doğal cevap dönelim
        examples = [
            f"I've noticed my neighbor is quite {word.english}, especially during community meetings.",
            f"Komşumun özellikle topluluk toplantılarında oldukça {word.turkish} olduğunu fark ettim.",
            f"The new student was {word.english} at first, but became more talkative as the semester progressed.",
            f"Yeni öğrenci başta {word.turkish} idi, ancak dönem ilerledikçe daha konuşkan oldu."
        ]
        # Hata durumunda veritabanına kaydetmeyi deneyelim
        try:
            word.example_sentences = '|||'.join(examples)
            
            # Hata durumunda bile aktiviteyi kaydetmeyi dene
            activity = Activity(
                user_id=current_user.id,
                activity_type='example_added',
                word_id=word.id,
                details=json.dumps({
                    'examples_count': 2,
                    'level': word.level,
                    'error_recovery': True
                })
            )
            db.session.add(activity)
            db.session.commit()
        except:
            pass
        return jsonify(success=True, examples=examples)

@app.route('/api/daily-stats')
@login_required
def daily_stats():
    try:
        # Get today's words
        today = datetime.now().date()
        today_words = Word.query.filter(
            Word.user_id == current_user.id,
            db.func.date(Word.created_at) == today
        ).count()
        
        # Get total words
        total_words = Word.query.filter_by(user_id=current_user.id).count()
        
        # Get weekly total (last 7 days)
        week_ago = datetime.now() - timedelta(days=7)
        weekly_words = Word.query.filter(
            Word.user_id == current_user.id,
            Word.created_at >= week_ago
        ).count()
        
        # Calculate streak (consecutive days with words)
        streak = 0
        check_date = datetime.now().date()
        while True:
            day_words = Word.query.filter(
                Word.user_id == current_user.id,
                db.func.date(Word.created_at) == check_date
            ).count()
            
            if day_words > 0:
                streak += 1
                check_date -= timedelta(days=1)
            else:
                break
                
            # Limit to reasonable streak calculation
            if streak > 100:
                break
        
        # Calculate daily average (total words / days since first word)
        first_word = Word.query.filter_by(user_id=current_user.id).order_by(Word.created_at.asc()).first()
        if first_word:
            days_active = (datetime.now().date() - first_word.created_at.date()).days + 1
            daily_average = round(total_words / days_active, 1) if days_active > 0 else 0
        else:
            daily_average = 0
        
        # Get user's daily goal (default 10)
        daily_goal = session.get('daily_goal', 10)
        
        return jsonify({
            'currentWords': today_words,
            'dailyGoal': daily_goal,
            'streakCount': streak,
            'weeklyTotal': weekly_words,
            'totalWordsLearned': total_words,
            'averageDaily': daily_average
        })
        
    except Exception as e:
        print(f"Daily stats error: {str(e)}")
        return jsonify({
            'currentWords': 0,
            'dailyGoal': 10,
            'streakCount': 0,
            'weeklyTotal': 0,
            'totalWordsLearned': 0,
            'averageDaily': 0.0
        })

@app.route('/api/update-daily-goal', methods=['POST'])
@login_required
def update_daily_goal():
    try:
        data = request.get_json()
        daily_goal = int(data.get('dailyGoal', 10))
        
        # Validate goal
        if daily_goal < 1 or daily_goal > 100:
            return jsonify({'success': False, 'error': 'Invalid goal range'})
        
        # For now, we'll store it in session or handle it differently
        # Since User model doesn't have daily_goal field by default
        session['daily_goal'] = daily_goal
        
        return jsonify({'success': True, 'dailyGoal': daily_goal})
        
    except Exception as e:
        print(f"Update daily goal error: {str(e)}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/analyze_sentence', methods=['POST'])
def analyze_sentence():
    try:
        data = request.get_json()
        sentence = data.get('sentence', '')
        word = data.get('word', '')
        word_id = data.get('word_id')

        if not sentence or not word:
            return jsonify(success=False, error="Lütfen bir cümle yazın"), 400

        if word.lower() not in sentence.lower():
            return jsonify(success=False, error=f"Cümlede '{word}' kelimesi kullanılmalıdır"), 400

        # Add activity record for exercise
        if word_id and current_user.is_authenticated:
            try:
                # Find the word in database
                db_word = Word.query.filter_by(id=word_id, user_id=current_user.id).first()
                if db_word:
                    # Add activity for sentence exercise
                    activity = Activity(
                        user_id=current_user.id,
                        activity_type='sentence_exercise',
                        word_id=db_word.id,
                        details=json.dumps({
                            'sentence': sentence[:50] + '...' if len(sentence) > 50 else sentence,
                            'word': word,
                            'level': db_word.level
                        })
                    )
                    db.session.add(activity)
                    db.session.commit()
            except Exception as e:
                print(f"Error recording exercise activity: {e}")
                # Continue with analysis even if activity recording fails

        # Groq API kullan
        try:
            prompt = f'''Sen deneyimli bir İngilizce öğretmenisin. Bu cümleyi analiz et: "{sentence}"

Cümleyi '{word}' kelimesinin kullanımı açısından değerlendir ve samimi, eğitici bir geri bildirim ver.

EĞER CÜMLE DOĞRUYSA:
Tebrikler! Cümleniz gramer açısından doğru ve '{word}' kelimesini çok güzel kullanmışsınız. 
[Cümlenin Türkçe tercümesi]

EĞER CÜMLE HATALIYSA:
Cümlenizde küçük bir düzeltme yapalım:

• [Neyin yanlış olduğunu samimi şekilde açıkla]
• [Neden yanlış olduğunu basitçe anlat]
• [Doğru kullanım nasıl olmalı - örnek ver]

Doğru cümle: [Düzeltilmiş cümle]
Türkçesi: [Türkçe tercüme]

Bu tür cümlelerde dikkat edilmesi gereken: [Pratik tavsiye]

Yanıtını doğal Türkçe ile ver, öğretmen gibi samimi ol, teknik terim kullanma, motive edici ol. Madde işareti kullanabilirsin ama HATA:, SEBEP: gibi etiketler kullanma.'''

            groq_response = call_groq_api(prompt, max_tokens=400, temperature=0.1)

            if groq_response:
                return jsonify(success=True, analysis=groq_response.strip())
        except Exception as e:
            print(f"Groq API analysis failed: {e}")
        
        # Fallback analysis
        basic_analysis = f"""Cümlenizde '{word}' kelimesi güzel bir şekilde geçiyor ve temel gramer yapısı uygun görünüyor.

• Kelime kullanımı doğru yerde
• Cümle yapısı anlamlı

Şu anda detaylı AI analizi kullanılamıyor, daha kapsamlı geri bildirim için lütfen daha sonra tekrar deneyin."""
        return jsonify(success=True, analysis=basic_analysis)

    except Exception as e:
        print(f"Sentence analysis error: {str(e)}")
        return jsonify(success=False, error="Cümle analizi sırasında bir hata oluştu"), 500

@app.route('/speak/<word>')
def speak_word(word):
    try:
        async def generate_audio():
            voice = edge_tts.Communicate(text=word, voice="en-US-ChristopherNeural")
            audio_data = b''
            async for chunk in voice.stream():
                if chunk["type"] == "audio":
                    audio_data += chunk["data"]
            return audio_data

        # Run the async function using asyncio
        audio_data = asyncio.run(generate_audio())
        
        # Return audio data directly
        return send_file(
            io.BytesIO(audio_data),
            mimetype="audio/mp3",
            as_attachment=True,
            download_name=f"{word}.mp3"
        )
    except Exception as e:
        print(f"Error generating audio: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        # Backend functionality will be added later
        flash('If an account exists with this email, you will receive a password reset link.', 'success')
        return redirect(url_for('forgot_password'))
    return render_template('forgot-password.html')

@app.route('/privacy-policy')
def privacy_policy():
    return render_template('privacy-policy.html')

@app.route('/terms-of-service')
def terms_of_service():
    return render_template('terms-of-service.html')

@app.route('/cookie-policy')
def cookie_policy():
    return render_template('cookie-policy.html')

@app.route('/version')
def version():
    return render_template('version.html')

@app.route('/settings')
@login_required
def settings():
    return render_template('settings.html', user=current_user)

@app.route('/update-settings', methods=['POST'])
@login_required
def update_settings():
    try:
        # Get form data
        form_data = request.form
        user = User.query.get(current_user.id)
        
        # Update user settings
        new_level = form_data.get('language_level', 'A1')
        # Validate language level
        valid_levels = ['A1', 'A2', 'B1', 'B2', 'C1', 'C2']
        if new_level in valid_levels:
            # Eğer seviye değişti ise, değişim tarihini güncelle
            if user.language_level != new_level:
                user.level_changed_at = datetime.utcnow()
            user.language_level = new_level
            
            # Eğer level_changed_at değeri yoksa (eski kullanıcılar için) set et
            if not user.level_changed_at:
                user.level_changed_at = datetime.utcnow()
        else:
            user.language_level = 'A1'  # Default fallback
        user.daily_goal = int(form_data.get('daily_goal', 10))
        
        # Handle email notifications (convert checkbox to string value)
        if form_data.get('email_notifications'):
            user.email_notifications = 'Daily'
        else:
            user.email_notifications = 'Never'
            
        # Update email if changed and not a Google user
        if not user.google_id:
            new_email = form_data.get('email')
            if new_email and new_email != user.email:
                if not is_valid_email(new_email):
                    return jsonify(success=False, error="Invalid email format"), 400
                if User.query.filter(User.id != user.id, User.email == new_email).first():
                    return jsonify(success=False, error="Email already registered"), 400
                user.email = new_email
        
        db.session.commit()
        return jsonify(success=True, message="Settings updated successfully")
        
    except Exception as e:
        db.session.rollback()
        print(f"Update settings error: {str(e)}")
        return jsonify(success=False, error="An error occurred while updating settings"), 500

@app.route('/update-profile', methods=['POST'])
@login_required
def update_profile():
    try:
        data = request.form
        user = User.query.get(current_user.id)
        
        # Username validation and update
        new_username = data.get('username', '').strip()
        if new_username and new_username != user.username:
            if not is_valid_username(new_username):
                return jsonify(success=False, error="Invalid username format"), 400
            if User.query.filter(User.id != user.id, User.username == new_username).first():
                return jsonify(success=False, error="Username already taken"), 400
            user.username = new_username

        # Email validation and update (only for non-Google users)
        if not user.google_id:
            new_email = data.get('email', '').strip()
            if new_email and new_email != user.email:
                if not is_valid_email(new_email):
                    return jsonify(success=False, error="Invalid email format"), 400
                if User.query.filter(User.id != user.id, User.email == new_email).first():
                    return jsonify(success=False, error="Email already registered"), 400
                user.email = new_email

        # Update other settings
        new_level = data.get('language_level', 'A1')
        valid_levels = ['A1', 'A2', 'B1', 'B2', 'C1', 'C2']
        if new_level in valid_levels:
            user.language_level = new_level
        else:
            user.language_level = 'A1'
        user.daily_goal = int(data.get('daily_goal', '10 words per day').split()[0])  # Extract number from "10 words per day"
        user.email_notifications = data.get('email_notifications', 'Never')

        # Password update (only for non-Google users)
        current_password = data.get('current_password')
        new_password = data.get('new_password')
        if current_password and new_password and not user.google_id:
            if not user.check_password(current_password):
                return jsonify(success=False, error="Current password is incorrect"), 400
            if not is_valid_password(new_password):
                return jsonify(success=False, error="New password does not meet security requirements"), 400
            user.set_password(new_password)

        db.session.commit()
        return jsonify(success=True, message="Profile updated successfully")

    except Exception as e:
        db.session.rollback()
        print(f"Profile update error: {str(e)}")
        return jsonify(success=False, error="An error occurred while updating profile"), 500

@app.route('/share_sentence', methods=['POST'])
@login_required
def share_sentence():
    try:
        data = request.get_json()
        sentence = data.get('sentence', '').strip()
        word_id = data.get('word_id')
        
        if not sentence:
            return jsonify(success=False, error="Cümle boş olamaz"), 400
            
        if not word_id:
            return jsonify(success=False, error="Kelime ID gerekli"), 400
            
        # Check if word belongs to user
        word = Word.query.filter_by(id=word_id, user_id=current_user.id).first()
        if not word:
            return jsonify(success=False, error="Kelime bulunamadı"), 404
            
        # Check if sentence contains the word
        if word.english.lower() not in sentence.lower():
            return jsonify(success=False, error=f"Cümle '{word.english}' kelimesini içermelidir"), 400
            
        # Check if user already shared a sentence for this word
        existing_sentence = SharedSentence.query.filter_by(
            word_id=word_id, 
            user_id=current_user.id
        ).first()
        
        if existing_sentence:
            return jsonify(success=False, error="Bu kelime için zaten bir cümle paylaştınız"), 400
            
        # Create new shared sentence
        shared_sentence = SharedSentence(
            sentence=sentence,
            word_id=word_id,
            user_id=current_user.id
        )
        
        db.session.add(shared_sentence)
        
        # Add activity
        activity = Activity(
            user_id=current_user.id,
            activity_type='sentence_shared',
            word_id=word_id,
            details=json.dumps({
                'sentence': sentence[:50] + '...' if len(sentence) > 50 else sentence,
                'word': word.english
            })
        )
        db.session.add(activity)
        
        db.session.commit()
        
        return jsonify(success=True, message="Cümleniz başarıyla paylaşıldı!")
        
    except Exception as e:
        db.session.rollback()
        print(f"Share sentence error: {str(e)}")
        return jsonify(success=False, error="Paylaşım sırasında bir hata oluştu"), 500

@app.route('/get_shared_sentences/<int:word_id>')
def get_shared_sentences(word_id):
    try:
        # Get all shared sentences for this word
        shared_sentences = SharedSentence.query.filter_by(word_id=word_id)\
            .order_by(SharedSentence.likes.desc(), SharedSentence.created_at.desc())\
            .limit(10).all()
            
        sentences_data = []
        for sentence in shared_sentences:
            sentences_data.append(sentence.to_dict())
            
        return jsonify(success=True, sentences=sentences_data)
        
    except Exception as e:
        print(f"Get shared sentences error: {str(e)}")
        return jsonify(success=False, error="Cümleler yüklenirken hata oluştu"), 500

@app.route('/like_sentence/<int:sentence_id>', methods=['POST'])
@login_required
def like_sentence(sentence_id):
    try:
        # Check if sentence exists
        sentence = SharedSentence.query.get(sentence_id)
        if not sentence:
            return jsonify(success=False, error="Cümle bulunamadı"), 404
            
        # Check if user already liked this sentence
        existing_like = SentenceLike.query.filter_by(
            sentence_id=sentence_id,
            user_id=current_user.id
        ).first()
        
        if existing_like:
            # Unlike - remove the like
            db.session.delete(existing_like)
            sentence.likes = max(0, sentence.likes - 1)
            action = 'unliked'
        else:
            # Like - add the like
            new_like = SentenceLike(
                sentence_id=sentence_id,
                user_id=current_user.id
            )
            db.session.add(new_like)
            sentence.likes += 1
            action = 'liked'
            
        db.session.commit()
        
        return jsonify(success=True, action=action, likes=sentence.likes)
        
    except Exception as e:
        db.session.rollback()
        print(f"Like sentence error: {str(e)}")
        return jsonify(success=False, error="Beğeni işlemi sırasında hata oluştu"), 500

@app.route('/delete_shared_sentence/<int:sentence_id>', methods=['POST'])
@login_required
def delete_shared_sentence(sentence_id):
    try:
        # Check if sentence exists
        sentence = SharedSentence.query.get(sentence_id)
        if not sentence:
            return jsonify(success=False, error="Cümle bulunamadı"), 404
            
        # Check if user owns this sentence
        if sentence.user_id != current_user.id:
            return jsonify(success=False, error="Bu cümleyi silme yetkiniz yok"), 403
            
        # Delete related likes first
        SentenceLike.query.filter_by(sentence_id=sentence_id).delete()
        
        # Delete the sentence
        db.session.delete(sentence)
        db.session.commit()
        
        return jsonify(success=True, message="Cümle başarıyla silindi")
        
    except Exception as e:
        db.session.rollback()
        print(f"Delete shared sentence error: {str(e)}")
        return jsonify(success=False, error="Cümle silinirken hata oluştu"), 500

@app.route('/save_word/<int:word_id>', methods=['POST'])
@login_required
def save_word(word_id):
    try:
        # Check if word exists
        word = Word.query.filter_by(id=word_id, user_id=current_user.id).first()
        if not word:
            return jsonify(success=False, error="Kelime bulunamadı"), 404
            
        # Check if already saved
        existing_save = SavedWord.query.filter_by(
            word_id=word_id,
            user_id=current_user.id
        ).first()
        
        if existing_save:
            return jsonify(success=True, message="Bu kelime zaten kaydedilmiş")
            
        # Save the word
        saved_word = SavedWord(
            word_id=word_id,
            user_id=current_user.id
        )
        db.session.add(saved_word)
        db.session.commit()
        
        return jsonify(success=True, message="Kelime başarıyla kaydedildi")
        
    except Exception as e:
        db.session.rollback()
        print(f"Save word error: {str(e)}")
        return jsonify(success=False, error="Kelime kaydedilirken hata oluştu"), 500

@app.route('/unsave_word/<int:word_id>', methods=['POST'])
@login_required
def unsave_word(word_id):
    try:
        # Find the saved record
        saved_word = SavedWord.query.filter_by(
            word_id=word_id,
            user_id=current_user.id
        ).first()
        
        if not saved_word:
            return jsonify(success=False, error="Bu kelime kaydedilmemiş"), 404
            
        # Delete the saved record
        db.session.delete(saved_word)
        db.session.commit()
        
        return jsonify(success=True, message="Kelime kaydı kaldırıldı")
        
    except Exception as e:
        db.session.rollback()
        print(f"Unsave word error: {str(e)}")
        return jsonify(success=False, error="Kelime kaydı kaldırılırken hata oluştu"), 500

@app.route('/is_saved/<int:word_id>')
def is_saved(word_id):
    try:
        # Kullanıcı giriş yapmamışsa
        if not current_user.is_authenticated:
            return jsonify(success=True, saved=False)
            
        # Check if word is saved
        saved_word = SavedWord.query.filter_by(
            word_id=word_id,
            user_id=current_user.id
        ).first()
        
        return jsonify(success=True, saved=saved_word is not None)
        
    except Exception as e:
        print(f"Is saved check error: {str(e)}")
        return jsonify(success=False, error="Kontrol sırasında hata oluştu", saved=False)

@app.route('/saved_words')
@login_required
def saved_words():
    # Get all saved words
    saved = SavedWord.query.filter_by(user_id=current_user.id).order_by(SavedWord.created_at.desc()).all()
    
    # Get the word objects
    word_ids = [saved_item.word_id for saved_item in saved]
    words = Word.query.filter(Word.id.in_(word_ids)).all()
    
    # Order words by save date (most recent first)
    word_order = {word_id: i for i, word_id in enumerate(word_ids)}
    words.sort(key=lambda word: word_order.get(word.id, 0))
    
    return render_template('saved_words.html', words=words)

@app.route('/rooms')
@login_required
def rooms():
    try:
        # Kullanıcının üye olduğu odaları getir
        user_memberships = RoomMember.query.filter_by(user_id=current_user.id).all()
        user_room_ids = [member.room_id for member in user_memberships]
        
        # Kullanıcının üye olduğu odaları getir
        user_rooms = Room.query.filter(Room.id.in_(user_room_ids)).all()
        
        # Kullanıcının üye olmadığı TÜM odaları getir (katılma isteği gönderebilmek için)
        if user_room_ids:
            other_rooms = Room.query.filter(~Room.id.in_(user_room_ids)).all()
        else:
            other_rooms = Room.query.all()
        

        
        # Her oda için üye sayısını ve diğer bilgileri ekleyelim
        formatted_user_rooms = []
        for room in user_rooms:
            room_dict = room.to_dict()
            formatted_user_rooms.append(room_dict)
            
        formatted_other_rooms = []
        for room in other_rooms:
            room_dict = room.to_dict()
            
            # Bu oda için kullanıcının katılma isteği durumunu kontrol et
            existing_request = RoomInvitation.query.filter_by(
                room_id=room.id, 
                user_id=current_user.id,
                request_type='join_request'
            ).first()
            
            if existing_request:
                if existing_request.status == 'pending':
                    room_dict['join_request_status'] = 'pending'
                elif existing_request.status == 'accepted':
                    room_dict['join_request_status'] = 'accepted'
                elif existing_request.status == 'rejected':
                    room_dict['join_request_status'] = 'rejected'
            else:
                room_dict['join_request_status'] = None
            
            formatted_other_rooms.append(room_dict)
        
        return render_template('rooms.html', 
                               user_rooms=formatted_user_rooms, 
                               all_rooms=formatted_other_rooms)
                               
    except Exception as e:
        print(f"Rooms page error: {str(e)}")
        flash("Odalar yüklenirken bir hata oluştu.", "error")
        return redirect(url_for('dashboard'))

@app.route('/create_room', methods=['POST'])
@login_required
def create_room():
    try:
        data = request.get_json()
        name = data.get('name', '').strip()
        description = data.get('description', '').strip()
        member_ids = data.get('members', [])
        
        print(f"Creating room: {name}, {description}, with members: {member_ids}")
        
        # Validasyon
        if not name:
            return jsonify(success=False, error="Oda adı gereklidir"), 400
            
        # Yeni oda oluştur
        new_room = Room(
            name=name,
            description=description,
            created_by=current_user.id
        )
        db.session.add(new_room)
        db.session.flush()  # ID almak için flush yap
        
        print(f"Created room with ID: {new_room.id}")
        
        # Oda oluşturan kişiyi admin olarak ekle
        creator_membership = RoomMember(
            room_id=new_room.id,
            user_id=current_user.id,
            is_admin=True
        )
        db.session.add(creator_membership)
        
        # Seçilen kullanıcılara davet gönder
        for user_id in member_ids:
            try:
                user_id = int(user_id)  # ID'yi integer'a dönüştür
                if user_id != current_user.id:  # Kendisini tekrar ekleme
                    try:
                        # Kullanıcının var olup olmadığını kontrol et
                        user = User.query.get(user_id)
                        if user:
                            # Davet oluştur
                            invitation = RoomInvitation(
                                room_id=new_room.id,
                                user_id=user_id,
                                invited_by=current_user.id,
                                request_type='invitation',
                                status='pending'
                            )
                            db.session.add(invitation)
                            print(f"Sent invitation to user {user_id} for room {new_room.id}")
                        else:
                            print(f"User {user_id} not found")
                    except Exception as e:
                        print(f"Error sending invitation to user {user_id}: {str(e)}")
            except (ValueError, TypeError):
                print(f"Invalid user ID: {user_id}")
        
        db.session.commit()
        
        # Oda bilgilerini dict olarak döndür
        room_dict = new_room.to_dict()
        room_dict['created_at'] = room_dict['created_at'].strftime('%Y-%m-%d %H:%M:%S')
        
        return jsonify(success=True, room=room_dict)
        
    except Exception as e:
        db.session.rollback()
        print(f"Create room error: {str(e)}")
        return jsonify(success=False, error="Oda oluşturulurken bir hata oluştu"), 500

@app.route('/room/<int:room_id>')
@login_required
def room_detail(room_id):
    # Odayı getir
    room = Room.query.get_or_404(room_id)
    
    # Kullanıcının odaya üye olup olmadığını kontrol et
    is_member = RoomMember.query.filter_by(room_id=room_id, user_id=current_user.id).first() is not None
    
    # Kullanıcı üye değilse ve özel bir oda ise erişimi engelle
    if not is_member:
        flash("Bu odaya erişim izniniz yok.", "error")
        return redirect(url_for('rooms'))
    
    # Oda üyelerini getir
    members = User.query.join(RoomMember).filter(RoomMember.room_id == room_id).all()
    
    # Odadaki tüm üyelerin kelimelerini getir
    words = Word.query.join(User).join(RoomMember, User.id == RoomMember.user_id).filter(
        RoomMember.room_id == room_id
    ).order_by(Word.created_at.desc()).all()
    
    return render_template('room_detail.html', 
                           room=room, 
                           members=members, 
                           words=words,
                           is_admin=RoomMember.query.filter_by(room_id=room_id, user_id=current_user.id, is_admin=True).first() is not None)

# Kelime seviyesi için renk döndüren yardımcı fonksiyon
@app.template_filter('get_level_color')
def get_level_color(level):
    # Monokrom stil kullan
    level_colors = {
        'A1': 'bg-white/10 text-white/90 border border-white/20',
        'A2': 'bg-white/12 text-white/90 border border-white/20',
        'B1': 'bg-white/14 text-white/90 border border-white/20',
        'B2': 'bg-white/16 text-white/90 border border-white/20',
        'C1': 'bg-white/18 text-white/90 border border-white/20',
        'C2': 'bg-white/20 text-white/90 border border-white/20'
    }
    return level_colors.get(level, 'bg-white/10 text-white/90 border border-white/20')

@app.route('/add_member/<int:room_id>', methods=['POST'])
@login_required
def add_member(room_id):
    try:
        data = request.get_json()
        user_id = data.get('user_id')
        
        # user_id string olarak geldiyse int'e çevirelim
        if isinstance(user_id, str) and user_id.isdigit():
            user_id = int(user_id)
        
        # URL'den gelen user_id yoksa, mevcut kullanıcıyı kullan
        if not user_id:
            user_id = current_user.id
            
        print(f"Adding user {user_id} to room {room_id}")
        
        # Odayı getir
        room = Room.query.get_or_404(room_id)
        
        # Kullanıcının admin olup olmadığını kontrol et
        # Kendisini ekliyorsa kontrol etme
        if user_id != current_user.id:
            is_admin = RoomMember.query.filter_by(room_id=room_id, user_id=current_user.id, is_admin=True).first()
            if not is_admin:
                return jsonify(success=False, error="Bu işlem için yetkiniz yok"), 403
            
            # Kullanıcıyı getir
            user = User.query.get(user_id)
            if not user:
                return jsonify(success=False, error="Kullanıcı bulunamadı"), 404
                
            # Kullanıcı zaten üye mi kontrol et
            existing_member = RoomMember.query.filter_by(room_id=room_id, user_id=user_id).first()
            if existing_member:
                # Zaten üye ise başarılı dön (idempotent)
                return jsonify(success=True, member={
                    'id': user.id,
                    'username': user.username,
                    'profile_pic': user.profile_pic
                })
                
            # Davet oluştur
            invitation = RoomInvitation(
                room_id=room_id,
                user_id=user_id,
                invited_by=current_user.id
            )
            db.session.add(invitation)
            db.session.commit()
            
            return jsonify(success=True, message="Davet başarıyla gönderildi", invitation_id=invitation.id)
        else:
            # Kendi isteğiyle katılıyorsa davetleri kontrol et
            invitation = RoomInvitation.query.filter_by(
                room_id=room_id, 
                user_id=current_user.id, 
                status='pending'
            ).first()
            
            if invitation:
                # Daveti kabul et
                invitation.status = 'accepted'
                
                # Odaya üye olarak ekle
                new_member = RoomMember(
                    room_id=room_id,
                    user_id=current_user.id
                )
                db.session.add(new_member)
                db.session.commit()
                
                return jsonify(success=True, message="Odaya başarıyla katıldınız")
            else:
                # Kullanıcı zaten üye mi kontrol et
                existing_member = RoomMember.query.filter_by(room_id=room_id, user_id=current_user.id).first()
                if existing_member:
                    return jsonify(success=True, message="Zaten bu odanın üyesisiniz")
                
                # Tüm odalar için katılma isteği gönderme özelliği
                # Katılım isteği oluştur
                invitation = RoomInvitation(
                    room_id=room_id,
                    user_id=current_user.id,
                    invited_by=current_user.id,  # Kendi kendine davet (istek)
                    status='pending'
                )
                db.session.add(invitation)
                db.session.commit()
                
                return jsonify(success=True, message="Katılma isteğiniz oda yöneticisine gönderildi. Onaylandığında odaya katılabileceksiniz.")
        
    except Exception as e:
        db.session.rollback()
        print(f"Add member error: {str(e)}")
        return jsonify(success=False, error="Üye eklenirken bir hata oluştu"), 500

@app.route('/invite_to_room/<int:room_id>', methods=['POST'])
@login_required
def invite_to_room(room_id):
    try:
        data = request.get_json()
        user_id = data.get('user_id')
        
        if not user_id:
            return jsonify(success=False, error="Kullanıcı ID'si gerekli"), 400
            
        # Odayı getir
        room = Room.query.get_or_404(room_id)
        
        # Kullanıcının admin olup olmadığını kontrol et
        is_admin = RoomMember.query.filter_by(room_id=room_id, user_id=current_user.id, is_admin=True).first()
        is_creator = room.created_by == current_user.id
        
        if not is_admin and not is_creator:
            return jsonify(success=False, error="Bu işlem için yetkiniz yok"), 403
            
        # Kullanıcıyı getir
        user = User.query.get(user_id)
        if not user:
            return jsonify(success=False, error="Kullanıcı bulunamadı"), 404
            
        # Kullanıcı zaten üye mi kontrol et
        existing_member = RoomMember.query.filter_by(room_id=room_id, user_id=user_id).first()
        if existing_member:
            return jsonify(success=False, error="Kullanıcı zaten bu odanın üyesi"), 400
            
        # Zaten davet var mı kontrol et
        existing_invitation = RoomInvitation.query.filter_by(
            room_id=room_id, 
            user_id=user_id, 
            status='pending'
        ).first()
        
        if existing_invitation:
            return jsonify(success=False, error="Bu kullanıcıya zaten davet gönderilmiş"), 400
            
        # Davet oluştur
        invitation = RoomInvitation(
            room_id=room_id,
            user_id=user_id,
            invited_by=current_user.id
        )
        db.session.add(invitation)
        db.session.commit()
        
        return jsonify(success=True, message="Davet başarıyla gönderildi", invitation_id=invitation.id)
        
    except Exception as e:
        db.session.rollback()
        print(f"Invite to room error: {str(e)}")
        return jsonify(success=False, error="Davet gönderilirken bir hata oluştu"), 500


@app.route('/approve_join_request/<int:invitation_id>', methods=['POST'])
@login_required
def approve_join_request(invitation_id):
    try:
        # Join request'i getir
        join_request = RoomInvitation.query.get_or_404(invitation_id)
        
        # Bu bir join request mi kontrol et
        if join_request.request_type != 'join_request':
            return jsonify(success=False, error="Bu bir katılma isteği değil"), 400
        
        # Kullanıcının bu oda için admin yetkisi var mı kontrol et
        is_admin = RoomMember.query.filter_by(
            room_id=join_request.room_id, 
            user_id=current_user.id, 
            is_admin=True
        ).first()
        
        room = Room.query.get(join_request.room_id)
        is_creator = room and room.created_by == current_user.id
        
        # DEBUG: Permission kontrol bilgileri
        print(f"DEBUG approve_join_request:")
        print(f"  current_user.id: {current_user.id}")
        print(f"  join_request.room_id: {join_request.room_id}")
        print(f"  is_admin query result: {is_admin}")
        print(f"  room.created_by: {room.created_by if room else 'Room not found'}")
        print(f"  is_creator: {is_creator}")
        print(f"  has_permission: {bool(is_admin or is_creator)}")
        
        if not is_admin and not is_creator:
            return jsonify(success=False, error="Bu işlem için yetkiniz yok"), 403
        
        # Request durumunu kontrol et
        if join_request.status != 'pending':
            return jsonify(success=False, error="Bu istek daha önce yanıtlanmış"), 400
        
        # Zaten üye mi kontrol et
        existing_member = RoomMember.query.filter_by(
            room_id=join_request.room_id, 
            user_id=join_request.user_id
        ).first()
        if existing_member:
            return jsonify(success=False, error="Kullanıcı zaten bu odanın üyesi"), 400
        
        # Join request'i onayla
        join_request.status = 'accepted'
        
        # Kullanıcıyı oda üyesi yap
        new_member = RoomMember(
            room_id=join_request.room_id,
            user_id=join_request.user_id,
            is_admin=False
        )
        
        db.session.add(new_member)
        db.session.commit()
        
        return jsonify(success=True, message="Katılma isteği onaylandı")
        
    except Exception as e:
        db.session.rollback()
        print(f"Approve join request error: {str(e)}")
        return jsonify(success=False, error="Katılma isteği onaylanırken bir hata oluştu"), 500

@app.route('/reject_join_request/<int:invitation_id>', methods=['POST'])
@login_required
def reject_join_request(invitation_id):
    try:
        # Join request'i getir
        join_request = RoomInvitation.query.get_or_404(invitation_id)
        
        # Bu bir join request mi kontrol et
        if join_request.request_type != 'join_request':
            return jsonify(success=False, error="Bu bir katılma isteği değil"), 400
        
        # Kullanıcının bu oda için admin yetkisi var mı kontrol et
        is_admin = RoomMember.query.filter_by(
            room_id=join_request.room_id, 
            user_id=current_user.id, 
            is_admin=True
        ).first()
        
        room = Room.query.get(join_request.room_id)
        is_creator = room and room.created_by == current_user.id
        
        # DEBUG: Permission kontrol bilgileri
        print(f"DEBUG reject_join_request:")
        print(f"  current_user.id: {current_user.id}")
        print(f"  join_request.room_id: {join_request.room_id}")
        print(f"  is_admin query result: {is_admin}")
        print(f"  room.created_by: {room.created_by if room else 'Room not found'}")
        print(f"  is_creator: {is_creator}")
        print(f"  has_permission: {bool(is_admin or is_creator)}")
        
        if not is_admin and not is_creator:
            return jsonify(success=False, error="Bu işlem için yetkiniz yok"), 403
        
        # Request durumunu kontrol et
        if join_request.status != 'pending':
            return jsonify(success=False, error="Bu istek daha önce yanıtlanmış"), 400
        
        # Join request'i reddet
        join_request.status = 'rejected'
        db.session.commit()
        
        return jsonify(success=True, message="Katılma isteği reddedildi")
        
    except Exception as e:
        db.session.rollback()
        print(f"Reject join request error: {str(e)}")
        return jsonify(success=False, error="Katılma isteği reddedilirken bir hata oluştu"), 500

@app.route('/get_invitations')
@login_required
def get_invitations():
    try:
        # Kullanıcının bekleyen davetlerini getir
        pending_invitations = RoomInvitation.query.filter_by(
            user_id=current_user.id, 
            status='pending'
        ).order_by(RoomInvitation.created_at.desc()).all()
        
        # Onaylanan join request'leri kontrol et (otomatik redirect için)
        approved_join_requests = RoomInvitation.query.filter_by(
            user_id=current_user.id,
            status='accepted',
            request_type='join_request'
        ).all()
        
        # Onaylanan join request'leri işle (silmek için)
        approved_rooms = []
        for approved_request in approved_join_requests:
            approved_rooms.append(approved_request.room_id)
            # Onaylanan join request'i sil (artık gerek yok)
            db.session.delete(approved_request)
        
        if approved_join_requests:
            db.session.commit()
        
        # Davetleri formatla
        result = []
        for invitation in pending_invitations:
            room = Room.query.get(invitation.room_id)
            inviter = User.query.get(invitation.invited_by)
            
            result.append({
                'id': invitation.id,
                'room_id': invitation.room_id,
                'room_name': room.name if room else 'Silinmiş Oda',
                'invited_by': inviter.username if inviter else 'Bilinmeyen',
                'created_at': invitation.created_at.strftime('%d %b %Y')
            })
        
        return jsonify(success=True, invitations=result, approved_rooms=approved_rooms)
        
    except Exception as e:
        print(f"Get invitations error: {str(e)}")
        return jsonify(success=False, error="Davetler getirilirken bir hata oluştu"), 500

@app.route('/remove_member/<int:room_id>/<int:user_id>', methods=['POST'])
@login_required
def remove_member(room_id, user_id):
    try:
        # Odayı getir
        room = Room.query.get_or_404(room_id)
        
        # Kullanıcının admin olup olmadığını kontrol et (veya kendisini çıkarıyorsa izin ver)
        is_admin = RoomMember.query.filter_by(room_id=room_id, user_id=current_user.id, is_admin=True).first()
        
        if not is_admin and current_user.id != user_id:
            return jsonify(success=False, error="Bu işlem için yetkiniz yok"), 403
            
        # Üyeyi getir
        member = RoomMember.query.filter_by(room_id=room_id, user_id=user_id).first()
        if not member:
            return jsonify(success=False, error="Üye bulunamadı"), 404
            
        # Oda yaratıcısı çıkarılamaz
        if room.created_by == user_id:
            return jsonify(success=False, error="Oda yaratıcısı odadan çıkarılamaz"), 400
            
        # Üyeyi sil
        db.session.delete(member)
        db.session.commit()
        
        return jsonify(success=True)
        
    except Exception as e:
        db.session.rollback()
        print(f"Remove member error: {str(e)}")
        return jsonify(success=False, error="Üye çıkarılırken bir hata oluştu"), 500

@app.route('/delete_room/<int:room_id>', methods=['POST'])
@login_required
def delete_room(room_id):
    try:
        # Odayı getir
        room = Room.query.get_or_404(room_id)
        
        # Kullanıcı odanın yaratıcısı mı kontrol et
        if room.created_by != current_user.id:
            return jsonify(success=False, error="Bu işlem için yetkiniz yok"), 403
            
        # Odayı sil (üyeler cascade ile silinecek)
        db.session.delete(room)
        db.session.commit()
        
        return jsonify(success=True)
        
    except Exception as e:
        db.session.rollback()
        print(f"Delete room error: {str(e)}")
        return jsonify(success=False, error="Oda silinirken bir hata oluştu"), 500

@app.route('/search_users', methods=['GET'])
@login_required
def search_users():
    try:
        query = request.args.get('q', '').strip()
        
        if not query or len(query) < 2:
            return jsonify(success=True, users=[])
            
        # Kullanıcı ara
        users = User.query.filter(
            User.username.ilike(f'%{query}%') | 
            User.email.ilike(f'%{query}%')
        ).filter(
            User.id != current_user.id  # Kendisi hariç
        ).limit(10).all()
        
        # Sonuçları formatla
        results = [{
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'profile_pic': user.profile_pic
        } for user in users]
        
        return jsonify(success=True, users=results)
        
    except Exception as e:
        print(f"Search users error: {str(e)}")
        return jsonify(success=False, error="Kullanıcı arama sırasında bir hata oluştu"), 500

@app.route('/update_room/<int:room_id>', methods=['POST'])
@login_required
def update_room(room_id):
    try:
        # Get the room
        room = Room.query.get_or_404(room_id)
        
        # Check if the user is the room creator or admin
        is_admin = RoomMember.query.filter_by(room_id=room_id, user_id=current_user.id, is_admin=True).first()
        
        if room.created_by != current_user.id and not is_admin:
            return jsonify(success=False, error="Bu işlem için yetkiniz yok"), 403
            
        # Get the data from the request
        data = request.get_json()
        name = data.get('name')
        description = data.get('description')
        
        if not name or name.strip() == '':
            return jsonify(success=False, error="Oda adı boş olamaz"), 400
            
        # Update the room
        room.name = name
        room.description = description
        
        # Save the changes
        db.session.commit()
        
        # Return success
        return jsonify(success=True, room=room.to_dict())
        
    except Exception as e:
        db.session.rollback()
        print(f"Update room error: {str(e)}")
        return jsonify(success=False, error="Oda güncellenirken bir hata oluştu"), 500

@app.route('/get_room_invitations/<int:room_id>')
@login_required
def get_room_invitations(room_id):
    """Oda adminlerinin gönderdikleri davetleri getir (sadece invitation type)"""
    try:
        # Odayı getir
        room = Room.query.get_or_404(room_id)
        
        # Kullanıcının admin olup olmadığını kontrol et
        is_admin = RoomMember.query.filter_by(room_id=room_id, user_id=current_user.id, is_admin=True).first()
        is_creator = room.created_by == current_user.id
        
        if not is_admin and not is_creator:
            return jsonify(success=False, error="Bu işlem için yetkiniz yok"), 403
            
        # Sadece invitation tipindeki bekleyen davetleri getir
        invitations = RoomInvitation.query.filter_by(
            room_id=room_id, 
            status='pending',
            request_type='invitation'
        ).order_by(RoomInvitation.created_at.desc()).all()
        
        # Davetleri formatla
        result = []
        for invitation in invitations:
            invitee = User.query.get(invitation.user_id)
            inviter = User.query.get(invitation.invited_by)
            
            if invitee:
                result.append({
                    'id': invitation.id,
                    'user_id': invitee.id,
                    'username': invitee.username,
                    'email': invitee.email,
                    'profile_pic': invitee.profile_pic,
                    'invited_by': inviter.username if inviter else None,
                    'created_at': invitation.created_at.strftime('%d %b %Y'),
                    'is_join_request': False
                })
        
        return jsonify(success=True, invitations=result)
        
    except Exception as e:
        print(f"Get room invitations error: {str(e)}")
        return jsonify(success=False, error="Davetler getirilirken bir hata oluştu"), 500

@app.route('/get_join_requests/<int:room_id>')
@login_required
def get_join_requests(room_id):
    """Oda adminlerinin onaylaması gereken katılma isteklerini getir (sadece join_request type)"""
    try:
        # Odayı getir
        room = Room.query.get_or_404(room_id)
        
        # Kullanıcının admin olup olmadığını kontrol et
        is_admin = RoomMember.query.filter_by(room_id=room_id, user_id=current_user.id, is_admin=True).first()
        is_creator = room.created_by == current_user.id
        
        if not is_admin and not is_creator:
            return jsonify(success=False, error="Bu işlem için yetkiniz yok"), 403
            
        # Sadece join_request tipindeki bekleyen istekleri getir
        join_requests = RoomInvitation.query.filter_by(
            room_id=room_id, 
            status='pending',
            request_type='join_request'
        ).order_by(RoomInvitation.created_at.desc()).all()
        
        # İstekleri formatla
        result = []
        for request in join_requests:
            requester = User.query.get(request.user_id)
            
            if requester:
                result.append({
                    'id': request.id,
                    'user_id': requester.id,
                    'username': requester.username,
                    'email': requester.email,
                    'profile_pic': requester.profile_pic,
                    'created_at': request.created_at.strftime('%d %b %Y'),
                    'is_join_request': True
                })
        
        return jsonify(success=True, join_requests=result)
        
    except Exception as e:
        print(f"Get join requests error: {str(e)}")
        return jsonify(success=False, error="Katılma istekleri getirilirken bir hata oluştu"), 500

@app.route('/get_my_invitations')
@login_required
def get_my_invitations():
    """Kullanıcının aldığı davetleri getir (sadece invitation type - kabul etmesi gereken)"""
    try:
        # Kullanıcıya gelen bekleyen davetleri getir
        invitations = RoomInvitation.query.filter_by(
            user_id=current_user.id,
            status='pending',
            request_type='invitation'
        ).order_by(RoomInvitation.created_at.desc()).all()
        
        result = []
        approved_rooms = []
        
        for invitation in invitations:
            room = Room.query.get(invitation.room_id)
            inviter = User.query.get(invitation.invited_by)
            
            if room:
                result.append({
                    'id': invitation.id,
                    'room_id': room.id,
                    'room_name': room.name,
                    'room_description': room.description,
                    'invited_by': inviter.username if inviter else 'Bilinmeyen',
                    'created_at': invitation.created_at.strftime('%d %b %Y'),
                    'is_join_request': False
                })
        
        return jsonify(success=True, invitations=result, approved_rooms=approved_rooms)
        
    except Exception as e:
        print(f"Get my invitations error: {str(e)}")
        return jsonify(success=False, error="Davetler getirilirken bir hata oluştu"), 500

@app.route('/accept_invitation/<int:invitation_id>', methods=['POST'])
@login_required
def accept_invitation(invitation_id):
    """Kullanıcının aldığı daveti kabul et (invitation type)"""
    try:
        # Daveti getir
        invitation = RoomInvitation.query.get_or_404(invitation_id)
        
        # Bu bir invitation mı kontrol et
        if invitation.request_type != 'invitation':
            return jsonify(success=False, error="Bu bir davet değil"), 400
        
        # Bu davet bu kullanıcıya mı gönderilmiş kontrol et
        if invitation.user_id != current_user.id:
            return jsonify(success=False, error="Bu davet size ait değil"), 403
        
        # Zaten üye mi kontrol et
        existing_member = RoomMember.query.filter_by(
            room_id=invitation.room_id, 
            user_id=current_user.id
        ).first()
        if existing_member:
            return jsonify(success=False, error="Zaten bu odanın üyesisiniz"), 400
        
        # Daveti kabul et
        invitation.status = 'accepted'
        
        # Kullanıcıyı oda üyesi yap
        new_member = RoomMember(
            room_id=invitation.room_id,
            user_id=current_user.id,
            is_admin=False
        )
        
        db.session.add(new_member)
        db.session.commit()
        
        return jsonify(success=True, message="Davet kabul edildi, odaya katıldınız!")
        
    except Exception as e:
        db.session.rollback()
        print(f"Accept invitation error: {str(e)}")
        return jsonify(success=False, error="Davet kabul edilirken bir hata oluştu"), 500

@app.route('/reject_invitation/<int:invitation_id>', methods=['POST'])
@login_required
def reject_invitation(invitation_id):
    """Kullanıcının aldığı daveti reddet (invitation type)"""
    try:
        # Daveti getir
        invitation = RoomInvitation.query.get_or_404(invitation_id)
        
        # Bu bir invitation mı kontrol et
        if invitation.request_type != 'invitation':
            return jsonify(success=False, error="Bu bir davet değil"), 400
        
        # Bu davet bu kullanıcıya mı gönderilmiş kontrol et
        if invitation.user_id != current_user.id:
            return jsonify(success=False, error="Bu davet size ait değil"), 403
        
        # Daveti reddet
        invitation.status = 'rejected'
        db.session.commit()
        
        return jsonify(success=True, message="Davet reddedildi")
        
    except Exception as e:
        db.session.rollback()
        print(f"Reject invitation error: {str(e)}")
        return jsonify(success=False, error="Davet reddedilirken bir hata oluştu"), 500

@app.route('/request_join_room/<int:room_id>', methods=['POST'])
@login_required
def request_join_room(room_id):
    try:
        # Oda var mı kontrol et
        room = Room.query.get_or_404(room_id)
        
        # Zaten üye mi kontrol et
        existing_member = RoomMember.query.filter_by(room_id=room_id, user_id=current_user.id).first()
        if existing_member:
            return jsonify(success=False, error="Zaten bu odanın üyesisiniz"), 400
        
        # Zaten istek gönderilmiş mi kontrol et (herhangi bir durumda)
        existing_request = RoomInvitation.query.filter_by(
            room_id=room_id, 
            user_id=current_user.id
        ).first()
        
        if existing_request:
            if existing_request.status == 'pending':
                # Eğer join_request ise
                if existing_request.request_type == 'join_request':
                    return jsonify(success=False, error="Bu oda için zaten katılma isteği gönderilmiş"), 400
                # Eğer invitation ise
                else:
                    return jsonify(success=False, error="Bu oda için zaten bir davetiniz var"), 400
            elif existing_request.status == 'accepted':
                return jsonify(success=False, error="Bu oda için daha önce kabul edilmiş bir kaydınız var"), 400
            elif existing_request.status == 'rejected':
                # Reddedilmiş kayıt varsa, yeni join_request oluşturmaya izin ver
                # Eski kaydı güncelle
                existing_request.request_type = 'join_request'
                existing_request.status = 'pending'
                existing_request.invited_by = None
                existing_request.created_at = datetime.utcnow()
                db.session.commit()
                return jsonify(success=True, message="Katılma isteğiniz gönderildi. Oda yöneticisinin onayını bekleyin.")
        
        
        # Yeni katılma isteği oluştur
        join_request = RoomInvitation(
            room_id=room_id,
            user_id=current_user.id,
            invited_by=None,  # Join request olduğunu belirtmek için null
            request_type='join_request',
            status='pending'
        )
        
        db.session.add(join_request)
        db.session.commit()
        
        return jsonify(success=True, message="Katılma isteğiniz gönderildi. Oda yöneticisinin onayını bekleyin.")
        
    except Exception as e:
        db.session.rollback()
        print(f"Error in request_join_room: {str(e)}")
        return jsonify(success=False, error="Katılma isteği gönderilirken hata oluştu"), 500


# @app.before_request fonksiyonunu geçici olarak devre dışı bırak
# def update_user_activity():
#     """Kullanıcı aktivitesini güvenli şekilde güncelle"""
#     if current_user.is_authenticated and hasattr(current_user, 'last_seen'):
#         try:
#             # Sadece 1 dakikadan eski ise güncelle (performans için)
#             if not current_user.last_seen or (datetime.utcnow() - current_user.last_seen).total_seconds() > 60:
#                 current_user.last_seen = datetime.utcnow()
#                 db.session.commit()
#         except Exception as e:
#             # Hata durumunda sessizce geç, login'i bozma
#             db.session.rollback()
#             pass

def update_last_seen():
    """Manuel olarak last_seen güncelle"""
    if current_user.is_authenticated:
        try:
            current_user.last_seen = datetime.utcnow()
            db.session.commit()
        except:
            db.session.rollback()

if __name__ == '__main__':
    app.run(debug=True) 
