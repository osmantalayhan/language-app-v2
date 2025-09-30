// Modal functions
function openAddWordModal() {
    document.getElementById('addWordModal').classList.remove('hidden');
    document.getElementById('addWordModal').classList.add('flex');
    document.getElementById('englishWord').focus();
}

function closeAddWordModal() {
    document.getElementById('addWordModal').classList.add('hidden');
    document.getElementById('addWordModal').classList.remove('flex');
    document.getElementById('addWordForm').reset();
    document.getElementById('addWordError').classList.add('hidden');
    document.getElementById('addWordSuccess').classList.add('hidden');
}

// Header action functions
function toggleFilter() {
    // Filter implementation
    alert('Filtreleme özelliği yakında eklenecek');
}

function toggleSort() {
    // Sort implementation
    alert('Sıralama özelliği yakında eklenecek');
}

function toggleLearningStatus() {
    // Learning status view
    alert('Öğrenme durumu görünümü yakında eklenecek');
}

function startQuizMode() {
    // Quiz mode
    alert('Quiz modu yakında eklenecek');
}

// Initialize header buttons
document.addEventListener('DOMContentLoaded', function() {
    // Get all header buttons
    const filterBtn = document.querySelector('.header-btn[title="Filtreleme Seçenekleri"]');
    const sortBtn = document.querySelector('.header-btn[title="Sırala"]');
    const learningStatusBtn = document.querySelector('.header-btn[title="Öğrenme Durumu"]');
    const quizModeBtn = document.querySelector('.header-btn[title="Quiz Modu"]');

    // Add event listeners
    if (filterBtn) filterBtn.addEventListener('click', toggleFilter);
    if (sortBtn) sortBtn.addEventListener('click', toggleSort);
    if (learningStatusBtn) learningStatusBtn.addEventListener('click', toggleLearningStatus);
    if (quizModeBtn) quizModeBtn.addEventListener('click', startQuizMode);
    
    // Search functionality
    const searchInput = document.getElementById('searchInput');
    if (searchInput) {
        searchInput.addEventListener('input', function() {
            filterWords(this.value.toLowerCase());
        });
        
        // Focus search on '/' key press
        document.addEventListener('keydown', function(event) {
            if (event.key === '/' && document.activeElement !== searchInput) {
                event.preventDefault();
                searchInput.focus();
            }
        });
    }
});

// Filter words based on search input
function filterWords(searchTerm) {
    const wordCards = document.querySelectorAll('.word-card');
    const emptyState = document.querySelector('.empty-state');
    let hasVisibleCards = false;
    
    wordCards.forEach(card => {
        const title = card.querySelector('.word-title').textContent.toLowerCase();
        const translation = card.querySelector('.word-translation').textContent.toLowerCase();
        
        if (title.includes(searchTerm) || translation.includes(searchTerm)) {
            card.style.display = '';
            hasVisibleCards = true;
        } else {
            card.style.display = 'none';
        }
    });
    
    // Show/hide empty state based on search results
    if (emptyState) {
        if (wordCards.length > 0 && !hasVisibleCards) {
            // Create search empty state if it doesn't exist
            let searchEmptyState = document.getElementById('searchEmptyState');
            if (!searchEmptyState) {
                searchEmptyState = document.createElement('div');
                searchEmptyState.id = 'searchEmptyState';
                searchEmptyState.className = 'empty-state';
                searchEmptyState.innerHTML = `
                    <div class="empty-state-icon">
                        <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1">
                            <circle cx="11" cy="11" r="8"/>
                            <path d="M21 21l-4.35-4.35"/>
                        </svg>
                    </div>
                    <h3 class="empty-state-title">Sonuç bulunamadı</h3>
                    <p class="empty-state-description">Aramanızla eşleşen kelime bulunamadı</p>
                `;
                document.querySelector('.word-grid').appendChild(searchEmptyState);
            }
            searchEmptyState.style.display = 'flex';
        } else if (document.getElementById('searchEmptyState')) {
            document.getElementById('searchEmptyState').style.display = 'none';
        }
    }
}

// Add word function
async function addWord(event) {
    event.preventDefault();
    
    const englishWord = document.getElementById('englishWord').value.trim();
    if (!englishWord) {
        showError('Lütfen bir kelime girin');
        return;
    }

    // Show loading state
    const btn = document.getElementById('addWordBtn');
    const btnText = document.getElementById('addWordBtnText');
    const btnLoading = document.getElementById('addWordBtnLoading');
    
    btn.disabled = true;
    btnText.classList.add('hidden');
    btnLoading.classList.remove('hidden');

    try {
        const formData = new FormData();
        formData.append('english', englishWord);

        const response = await fetch('/add_word', {
            method: 'POST',
            body: formData
        });

        const data = await response.json();

        if (data.success) {
            showSuccess('Kelime başarıyla eklendi!');
            setTimeout(() => {
                location.reload(); // Sayfayı yenile
            }, 1500);
        } else {
            showError(data.error || 'Kelime eklenirken bir hata oluştu');
        }
    } catch (error) {
        console.error('Error:', error);
        showError('Bağlantı hatası. Lütfen tekrar deneyin.');
    } finally {
        // Reset loading state
        btn.disabled = false;
        btnText.classList.remove('hidden');
        btnLoading.classList.add('hidden');
    }
}

function showError(message) {
    const errorDiv = document.getElementById('addWordError');
    const successDiv = document.getElementById('addWordSuccess');
    
    successDiv.classList.add('hidden');
    errorDiv.textContent = message;
    errorDiv.classList.remove('hidden');
}

function showSuccess(message) {
    const errorDiv = document.getElementById('addWordError');
    const successDiv = document.getElementById('addWordSuccess');
    
    errorDiv.classList.add('hidden');
    successDiv.textContent = message;
    successDiv.classList.remove('hidden');
}

// Kelime detayına git
function goToWordDetail(wordId) {
    window.location.href = `/word/${wordId}`;
}

// Kelimeyi tekrar için işaretle
async function markAsReview(wordId) {
    try {
        const response = await fetch(`/mark_review/${wordId}`, {
            method: 'POST'
        });
        const data = await response.json();
        if (data.success) {
            location.reload();
        }
    } catch (error) {
        console.error('Error marking as review:', error);
    }
}

// Kelimeyi kaydet/kayıttan çıkar
async function toggleSaveWord(wordId) {
    try {
        const saveBtn = document.getElementById(`save-btn-${wordId}`);
        const isSaved = saveBtn.classList.contains('active');
        
        let response;
        if (isSaved) {
            // Kayıttan çıkar
            response = await fetch(`/unsave_word/${wordId}`, {
                method: 'POST'
            });
        } else {
            // Kaydet
            response = await fetch(`/save_word/${wordId}`, {
                method: 'POST'
            });
        }
        
        const data = await response.json();
        
        if (data.success) {
            // Buton durumunu değiştir
            saveBtn.classList.toggle('active');
        }
    } catch (error) {
        console.error('Error:', error);
        alert('Bağlantı hatası. Lütfen tekrar deneyin.');
    }
}

// Kelime kartları ilk yüklendiğinde kaydedilmiş durumlarını kontrol et
document.addEventListener('DOMContentLoaded', function() {
    const wordCards = document.querySelectorAll('.word-card');
    
    wordCards.forEach(card => {
        const wordIdMatch = card.getAttribute('onclick').match(/\d+/);
        if (wordIdMatch) {
            const wordId = wordIdMatch[0];
            const saveBtn = document.getElementById(`save-btn-${wordId}`);
            
            if (saveBtn) {
                // Kelime kaydedilmiş mi kontrol et
                fetch(`/is_saved/${wordId}`)
                    .then(response => response.json())
                    .then(data => {
                        if (data.success && data.saved) {
                            saveBtn.classList.add('active');
                        }
                    })
                    .catch(error => console.error('Error checking saved status:', error));
            }
        }
    });
});

// Kelimeyi sil
async function deleteWord(wordId) {
    try {
        const response = await fetch(`/delete_word/${wordId}`, {
            method: 'POST'
        });
        const data = await response.json();
        if (data.success) {
            location.reload();
        } else {
            alert('Kelime silinirken hata oluştu: ' + (data.error || 'Bilinmeyen hata'));
        }
    } catch (error) {
        console.error('Error deleting word:', error);
        alert('Bağlantı hatası. Lütfen tekrar deneyin.');
    }
}

// Show delete confirmation modal
function showDeleteModal(e, wordId) {
    // Prevent event bubbling
    if (e) {
        e.stopPropagation();
    }
    
    // Show the modal
    const modal = document.getElementById('delete-modal');
    modal.classList.add('active');
    
    // Set up event listeners
    document.getElementById('modal-cancel').onclick = function() {
        modal.classList.remove('active');
    };
    
    document.getElementById('modal-delete').onclick = function() {
        // Hide the modal
        modal.classList.remove('active');
        
        // Delete the word
        deleteWord(wordId);
    };
}

// Ses çalma fonksiyonu
function playAudio(word) {
    try {
        // Web Speech API kullan (tarayıcı desteği)
        if ('speechSynthesis' in window) {
            // Önce konuşmayı durdur
            speechSynthesis.cancel();
            
            const utterance = new SpeechSynthesisUtterance(word);
            utterance.lang = 'en-US';
            utterance.rate = 0.8; // Biraz yavaş konuş
            utterance.pitch = 1.0;
            utterance.volume = 1.0;
            
            speechSynthesis.speak(utterance);
        } else {
            // Fallback: Edge TTS servisi dene
            fetch(`/speak/${encodeURIComponent(word)}`)
                .then(response => {
                    if (!response.ok) {
                        throw new Error('Audio service unavailable');
                    }
                    return response.blob();
                })
                .then(blob => {
                    const audio = new Audio(URL.createObjectURL(blob));
                    audio.play();
                })
                .catch(error => {
                    console.error('Error playing audio:', error);
                    alert('Ses çalma servisi şu anda kullanılamıyor. Lütfen daha sonra tekrar deneyin.');
                });
        }
    } catch (error) {
        console.error('Error in playAudio function:', error);
        alert('Ses çalma işleminde bir hata oluştu.');
    }
}

// ESC tuşu ile modal kapatma
document.addEventListener('keydown', function(event) {
    if (event.key === 'Escape') {
        closeAddWordModal();
    }
});

// Modal dışına tıklayınca kapatma
document.getElementById('addWordModal').addEventListener('click', function(event) {
    if (event.target === this) {
        closeAddWordModal();
    }
});