//QUIZ
import { allQuestions } from './questions.js';

// --- Global Variables & Constants ---
const QUESTION_COUNT = 10;
const TIME_LIMIT = 30;
const STORAGE_KEY = 'cybersecurityQuizData';
let currentQuestionIndex = 0;
let score = 0;
let selectedAnswer = null;
let topicErrors = {}; 
let randomizedQuizData = []; 
let timer;
let currentStreak = 0;
let bestStreak = 0;
let userAnswers = [];

// --- Power-ups ---
const powerUps = {
    doublePoints: {
        name: 'Double Points',
        icon: '⚡',
        count: 2,
        description: 'Double points for next correct answer',
        active: false
    },
    timeFreeze: {
        name: 'Time Freeze',
        icon: '⏸️',
        count: 1,
        description: 'Freeze timer for 10 seconds',
        active: false
    },
    removeTwo: {
        name: 'Remove Two',
        icon: '❌',
        count: 1,
        description: 'Remove two wrong answers',
        active: false
    }
};

// --- DOM Element References ---
const questionEl = document.getElementById('question');
const optionsContainer = document.getElementById('options-container');
const submitBtn = document.getElementById('submit-btn');
const nextBtn = document.getElementById('next-btn');
const feedbackEl = document.getElementById('feedback');
const feedbackMessageEl = document.getElementById('feedback-message');
const explanationTextEl = document.getElementById('explanation-text');
const resultContainer = document.getElementById('result-container');
const quizEl = document.getElementById('quiz');
const scoreText = document.getElementById('score-text');
const restartBtn = document.getElementById('restart-btn');
const percentageText = document.getElementById('percentage-text');
const generalFeedback = document.getElementById('general-feedback');
const topicList = document.getElementById('topic-list');
const timerProgress = document.getElementById('timer-progress');
const themeToggle = document.getElementById('theme-toggle');
const shareBtn = document.getElementById('share-btn');
const reviewBtn = document.getElementById('review-btn');
const reviewContainer = document.getElementById('review-container');
const reviewQuestionsEl = document.getElementById('review-questions');
const closeReviewBtn = document.getElementById('close-review');
const currentQuestionNumEl = document.getElementById('current-question-num');
const totalQuestionsEl = document.getElementById('total-questions');
const currentScoreEl = document.getElementById('current-score');
const streakCounterEl = document.getElementById('streak-counter');

// --- Audio Context for Sound Effects ---
const audioContext = new (window.AudioContext || window.webkitAudioContext)();

// --- TIMER FUNCTIONS ---
function startTimer() {
    let timeLeft = TIME_LIMIT;
    if (timerProgress) {
        timerProgress.style.transition = 'none';
        timerProgress.style.width = '100%';
        timerProgress.style.backgroundColor = '#ff9800';
    }
    
    stopTimer();
    
    timer = setInterval(() => {
        timeLeft--;
        const percentage = (timeLeft / TIME_LIMIT) * 100;
        
        if (timerProgress) {
            timerProgress.style.transition = 'width 1s linear';
            timerProgress.style.width = `${percentage}%`;

            if (timeLeft <= 10) {
                timerProgress.style.backgroundColor = '#d32f2f';
            }
        }

        if (timeLeft <= 0) {
            stopTimer();
            selectedAnswer = null;
            checkAnswer(true);
        }
    }, 1000);
}

function stopTimer() {
    clearInterval(timer);
}

// --- CONFETTI ANIMATION ---
function triggerConfetti() {
    if (typeof confetti === 'function') {
        confetti({
            particleCount: 150,
            spread: 90,
            origin: { y: 0.6 },
            colors: ['#00bcd4', '#4caf50', '#ffeb3b', '#ffffff']
        });
    }
}

// --- SOUND EFFECTS ---
function playSound(frequency, duration, type = 'sine') {
    if (audioContext.state === 'suspended') {
        audioContext.resume();
    }
    
    try {
        const oscillator = audioContext.createOscillator();
        const gainNode = audioContext.createGain();
        
        oscillator.connect(gainNode);
        gainNode.connect(audioContext.destination);
        
        oscillator.frequency.value = frequency;
        oscillator.type = type;
        
        gainNode.gain.setValueAtTime(0.3, audioContext.currentTime);
        gainNode.gain.exponentialRampToValueAtTime(0.01, audioContext.currentTime + duration);
        
        oscillator.start(audioContext.currentTime);
        oscillator.stop(audioContext.currentTime + duration);
    } catch (error) {
        console.log('Audio error:', error);
    }
}

// --- POWER-UP SYSTEM ---
function createPowerUpUI() {
    const container = document.createElement('div');
    container.className = 'power-up-container';
    container.id = 'power-up-container';
    
    Object.keys(powerUps).forEach(key => {
        const powerUp = powerUps[key];
        const button = document.createElement('button');
        button.className = 'power-up';
        button.id = `power-up-${key}`;
        button.innerHTML = `
            <div class="power-up-icon">${powerUp.icon}</div>
            <div class="power-up-count">${powerUp.count}</div>
            <div class="power-up-tooltip">${powerUp.description}</div>
        `;
        
        button.addEventListener('click', () => activatePowerUp(key));
        button.disabled = powerUp.count === 0;
        
        container.appendChild(button);
    });
    
    // Insert power-ups after timer bar
    const timerBar = document.getElementById('timer-bar');
    timerBar.insertAdjacentElement('afterend', container);
}

function activatePowerUp(type) {
    if (powerUps[type].count <= 0) return;
    
    switch(type) {
        case 'doublePoints':
            powerUps[type].active = true;
            playSound(880, 0.3, 'triangle');
            break;
            
        case 'timeFreeze':
            const currentWidth = parseInt(timerProgress.style.width) || 100;
            const newWidth = Math.min(currentWidth + 33, 100);
            timerProgress.style.width = `${newWidth}%`;
            playSound(659.25, 0.5);
            break;
            
        case 'removeTwo':
            const correctAnswer = randomizedQuizData[currentQuestionIndex].answer;
            const optionButtons = document.querySelectorAll('.option-btn');
            const wrongOptions = [];
            
            // Collect all wrong options that are not already disabled
            optionButtons.forEach(btn => {
                if (btn.textContent !== correctAnswer && 
                    !btn.disabled && 
                    btn.style.opacity !== '0.3') {
                    wrongOptions.push(btn);
                }
            });
            
            // Ensure we have at least 2 wrong options to remove
            if (wrongOptions.length >= 2) {
                // Randomly select 2 distinct wrong options
                const shuffled = [...wrongOptions].sort(() => 0.5 - Math.random());
                const optionsToRemove = shuffled.slice(0, 2);
                
                optionsToRemove.forEach(btn => {
                    btn.style.opacity = '0.3';
                    btn.style.pointerEvents = 'none';
                    btn.style.transition = 'opacity 0.3s ease';
                });
                
                playSound(220, 0.2, 'sawtooth');
                
                // If user had selected one of these, deselect it
                if (selectedAnswer && optionsToRemove.some(btn => btn.textContent === selectedAnswer)) {
                    document.querySelectorAll('.option-btn').forEach(btn => btn.classList.remove('selected'));
                    selectedAnswer = null;
                    submitBtn.disabled = true;
                }
            } else {
                // Not enough wrong options - refund the power-up
                powerUps[type].count++;
                updatePowerUpUI();
                playSound(220, 0.5, 'square'); // Error sound
                return;
            }
            break;
    }
    
    powerUps[type].count--;
    updatePowerUpUI();
}

function updatePowerUpUI() {
    Object.keys(powerUps).forEach(key => {
        const button = document.getElementById(`power-up-${key}`);
        if (button) {
            const countEl = button.querySelector('.power-up-count');
            countEl.textContent = powerUps[key].count;
            button.disabled = powerUps[key].count === 0;
        }
    });
}

// --- THEME SYSTEM ---
function initTheme() {
    const savedTheme = localStorage.getItem('quizTheme') || 'dark';
    document.body.classList.toggle('light-theme', savedTheme === 'light');
    themeToggle.textContent = savedTheme === 'dark' ? '🌓' : '🌙';
}

// --- LOCAL STORAGE FUNCTIONS ---
function saveHighScore(percentage, score, total) {
    const data = {
        date: new Date().toISOString(),
        percentage: percentage,
        score: score,
        total: total,
        streak: bestStreak
    };
    
    const existingData = JSON.parse(localStorage.getItem(STORAGE_KEY)) || [];
    existingData.push(data);
    
    if (existingData.length > 10) {
        existingData.shift();
    }
    
    localStorage.setItem(STORAGE_KEY, JSON.stringify(existingData));
}

function getBestScore() {
    const data = JSON.parse(localStorage.getItem(STORAGE_KEY)) || [];
    if (data.length === 0) return 0;
    
    return Math.max(...data.map(item => item.percentage));
}

// --- SHARE RESULTS ---
function shareResults() {
    const totalQuestions = randomizedQuizData.length;
    const percentage = Math.round((score / totalQuestions) * 100);
    const topics = Object.keys(topicErrors);
    
    let topicSummary = '';
    if (topics.length > 0) {
        const worstTopic = topics.sort((a, b) => topicErrors[b] - topicErrors[a])[0];
        topicSummary = `Most challenging: ${worstTopic}`;
    } else {
        topicSummary = 'Perfect score! 🎯';
    }
    
    const shareText = `I scored ${percentage}% on the Cybersecurity Quiz! ${topicSummary}\n\nTest your knowledge at: ${window.location.href}`;
    
    if (navigator.share) {
        navigator.share({
            title: 'Cybersecurity Quiz Results',
            text: shareText,
            url: window.location.href
        }).catch(err => {
            console.log('Error sharing:', err);
            fallbackShare(shareText);
        });
    } else {
        fallbackShare(shareText);
    }
}

function fallbackShare(text) {
    navigator.clipboard.writeText(text).then(() => {
        alert('Results copied to clipboard! 📋');
    }).catch(err => {
        const textArea = document.createElement('textarea');
        textArea.value = text;
        document.body.appendChild(textArea);
        textArea.select();
        document.execCommand('copy');
        document.body.removeChild(textArea);
        alert('Results copied to clipboard! 📋');
    });
}

// --- QUESTION REVIEW ---
function showReview() {
    reviewContainer.classList.remove('hidden');
    reviewQuestionsEl.innerHTML = '';
    
    randomizedQuizData.forEach((q, index) => {
        const userAnswer = getUserAnswerForQuestion(index);
        const isCorrect = userAnswer === q.answer;
        
        const questionDiv = document.createElement('div');
        questionDiv.className = 'review-question';
        questionDiv.innerHTML = `
            <div class="review-question-header ${isCorrect ? 'correct' : 'incorrect'}">
                <strong>Q${index + 1}:</strong> ${q.question}
                <span class="review-status">${isCorrect ? '✅' : '❌'}</span>
            </div>
            <div class="review-options">
                ${q.options.map(option => {
                    let className = '';
                    if (option === q.answer) className = 'correct-answer';
                    if (option === userAnswer && !isCorrect) className = 'user-answer-incorrect';
                    return `<div class="review-option ${className}">${option}</div>`;
                }).join('')}
            </div>
            <div class="review-explanation">
                <strong>Explanation:</strong> ${q.explanation}
            </div>
            <hr>
        `;
        reviewQuestionsEl.appendChild(questionDiv);
    });
}

function getUserAnswerForQuestion(index) {
    return userAnswers[index] ? userAnswers[index].answer : 'No answer';
}

// --- KEYBOARD NAVIGATION ---
function setupKeyboardNavigation() {
    document.addEventListener('keydown', (e) => {
        // Only work when quiz is active (results hidden) AND review is also hidden
        if (resultContainer.classList.contains('hidden') && 
            reviewContainer.classList.contains('hidden')) {
            
            // Prevent default for number keys only
            if (['1', '2', '3', '4', 'Enter', ' '].includes(e.key)) {
                e.preventDefault();
            }
            
            // 1-4 keys to select options
            if (['1', '2', '3', '4'].includes(e.key)) {
                const index = parseInt(e.key) - 1;
                const buttons = document.querySelectorAll('.option-btn');
                if (buttons[index] && !buttons[index].disabled) {
                    buttons[index].click();
                }
            }
            
            // Enter key: submit answer or go to next question
            if (e.key === 'Enter') {
                if (!feedbackEl.classList.contains('hidden') && !nextBtn.classList.contains('hidden')) {
                    // After answer submission - go to next question
                    nextBtn.click();
                } else if (!submitBtn.disabled && feedbackEl.classList.contains('hidden')) {
                    // During question - submit answer
                    submitBtn.click();
                }
            }
            
            // Space key: submit answer only (not next)
            if (e.key === ' ') {
                if (!submitBtn.disabled && feedbackEl.classList.contains('hidden')) {
                    submitBtn.click();
                }
            }
        }
    });
}

// --- HELPER FUNCTIONS ---
function getRandomQuestions(array, count) {
    let shuffled = array.slice();
    let i = array.length;
    let temp, randIndex;

    while (i > 0) {
        randIndex = Math.floor(Math.random() * i);
        i--;
        temp = shuffled[i];
        shuffled[i] = shuffled[randIndex];
        shuffled[randIndex] = temp;
    }

    return shuffled.slice(0, count);
}

// --- MAIN QUIZ FUNCTIONS ---
function loadQuestion() {
    stopTimer();

    if (randomizedQuizData.length === 0) {
        if (!allQuestions || allQuestions.length === 0) {
            questionEl.textContent = "Error: Question data file is empty or improperly loaded.";
            return;
        }
        randomizedQuizData = getRandomQuestions(allQuestions, QUESTION_COUNT);
        quizEl.classList.remove('hidden');
        resultContainer.classList.add('hidden');
    }
    
    if (currentQuestionIndex >= randomizedQuizData.length) {
        showResults();
        return;
    }

    const currentQuestion = randomizedQuizData[currentQuestionIndex];
    
    // Reset UI for new question
    optionsContainer.innerHTML = '';
    feedbackEl.classList.add('hidden');
    feedbackEl.className = 'hidden';
    submitBtn.disabled = true;
    nextBtn.classList.add('hidden');
    selectedAnswer = null;

    // Update progress indicators
    currentQuestionNumEl.textContent = currentQuestionIndex + 1;
    totalQuestionsEl.textContent = QUESTION_COUNT;
    currentScoreEl.innerHTML = `Score: <span>${score}</span>`;
    streakCounterEl.innerHTML = `Streak: <span>${currentStreak}</span> 🔥`;

    // Display question
    questionEl.textContent = `Q${currentQuestionIndex + 1}: ${currentQuestion.question}`;

    // Create option buttons
    currentQuestion.options.forEach(option => {
        const button = document.createElement('button');
        button.classList.add('option-btn');
        button.textContent = option;
        button.addEventListener('click', () => selectOption(button, option));
        optionsContainer.appendChild(button);
    });

    // Start timer
    startTimer();
}

function selectOption(button, option) {
    document.querySelectorAll('.option-btn').forEach(btn => {
        btn.classList.remove('selected');
        // Reset any power-up effects on new selection
        if (btn.style.opacity === '0.3') {
            btn.style.opacity = '1';
            btn.style.pointerEvents = 'auto';
        }
    });
    button.classList.add('selected');
    selectedAnswer = option;
    submitBtn.disabled = false;
}

function checkAnswer(isTimeout = false) {
    stopTimer();

    if (!selectedAnswer && !isTimeout) return;

    const currentQuestion = randomizedQuizData[currentQuestionIndex];
    const isCorrect = selectedAnswer === currentQuestion.answer;
    
    // Store user's answer
    userAnswers[currentQuestionIndex] = {
        answer: selectedAnswer,
        isTimeout: isTimeout,
        topic: currentQuestion.topic
    };

    document.querySelectorAll('.option-btn').forEach(btn => btn.disabled = true);
    submitBtn.disabled = true;

    feedbackEl.classList.remove('hidden');
    nextBtn.classList.remove('hidden');
    
    let pointsEarned = 1;
    if (isCorrect) {
        // Apply double points power-up
        if (powerUps.doublePoints.active) {
            pointsEarned = 2;
            powerUps.doublePoints.active = false;
        }
        
        score += pointsEarned;
        feedbackMessageEl.textContent = `✅ Correct! ${pointsEarned === 2 ? '⚡ Double points! ' : ''}Great job.`;
        feedbackEl.classList.add('correct');
        
        // Update streak
        currentStreak++;
        if (currentStreak > bestStreak) bestStreak = currentStreak;
        streakCounterEl.classList.add('streak-pop');
        setTimeout(() => streakCounterEl.classList.remove('streak-pop'), 500);
        
        // Play sound
        playSound(523.25, 0.5); // C5
        playSound(659.25, 0.5, 'triangle'); // E5
        
        // Trigger confetti ONLY on streaks of 3 or more
        if (currentStreak >= 3) {
            triggerConfetti();
        }
    } else {
        feedbackEl.classList.add('incorrect');
        
        if (isTimeout) {
            feedbackMessageEl.textContent = `⏱️ Time's up! The correct answer was: ${currentQuestion.answer}`;
        } else {
            feedbackMessageEl.textContent = `❌ Incorrect! The correct answer was: ${currentQuestion.answer}`;
        }
        
        // Log error
        const topic = currentQuestion.topic || 'Uncategorized';
        topicErrors[topic] = (topicErrors[topic] || 0) + 1;
        
        // Reset streak
        currentStreak = 0;
        
        // Play error sound
        playSound(220, 0.8, 'square'); // A3
        
        // Highlight answers
        document.querySelectorAll('.option-btn').forEach(btn => {
            if (btn.textContent === currentQuestion.answer) {
                btn.style.backgroundColor = '#1a5e20';
                btn.style.color = 'white';
            } else if (btn.textContent === selectedAnswer && !isTimeout) {
                btn.style.backgroundColor = '#7f2020';
                btn.style.color = 'white';
            }
        });
    }
    
    // Update UI immediately
    currentScoreEl.innerHTML = `Score: <span>${score}</span>`;
    streakCounterEl.innerHTML = `Streak: <span>${currentStreak}</span> 🔥`;
    explanationTextEl.textContent = currentQuestion.explanation;
}

function showResults() {
    const totalQuestions = randomizedQuizData.length;
    const percentage = Math.round((score / totalQuestions) * 100);
    const bestScore = getBestScore();

    quizEl.classList.add('hidden');
    resultContainer.classList.remove('hidden');
    
    // Save to localStorage
    saveHighScore(percentage, score, totalQuestions);
    
    // Clean consolidated display - FIXED: Remove redundant percentage-text update
    scoreText.innerHTML = `
        <div class="score-summary">
            <p>You answered <strong>${score}</strong> out of <strong>${totalQuestions}</strong> questions correctly.</p>
            <p class="overall-score">Overall Score: <strong>${percentage}%</strong></p>
            <div class="score-details">
                <span class="best-score">🏆 Best: ${bestScore}%</span>
                <span class="best-streak">🔥 Streak: ${bestStreak}</span>
            </div>
        </div>
    `;

    // General feedback
    if (percentage >= 80) {
        generalFeedback.textContent = "Excellent work! Your cybersecurity knowledge is strong. Keep it up!";
        generalFeedback.style.color = '#4caf50';
        playSound(880, 1, 'sine');
    } else if (percentage >= 60) {
        generalFeedback.textContent = "Good job! You have a solid grasp of the basics. Review improvement areas to reach expert level.";
        generalFeedback.style.color = '#ff9800';
    } else {
        generalFeedback.textContent = "Requires more focus. Review the concepts below and practice to improve your core understanding.";
        generalFeedback.style.color = '#d32f2f';
    }

    // Topic feedback
    topicList.innerHTML = '';
    const errorTopics = Object.keys(topicErrors);

    if (errorTopics.length > 0) {
        errorTopics.sort((a, b) => topicErrors[b] - topicErrors[a]);
        
        errorTopics.forEach(topic => {
            const errorCount = topicErrors[topic];
            const listItem = document.createElement('li');
            listItem.textContent = `📌 ${topic} (Incorrect: ${errorCount} question${errorCount > 1 ? 's' : ''})`;
            topicList.appendChild(listItem);
        });
    } else {
        const listItem = document.createElement('li');
        listItem.textContent = "No specific areas for improvement identified. Perfect score!";
        listItem.style.backgroundColor = '#1a5e20';
        listItem.style.color = '#c8e6c9';
        listItem.style.borderLeft = '5px solid #388e3c';
        topicList.appendChild(listItem);
    }
}

function restartQuiz() {
    stopTimer();
    currentQuestionIndex = 0;
    score = 0;
    selectedAnswer = null;
    topicErrors = {};
    randomizedQuizData = [];
    userAnswers = [];
    currentStreak = 0;
    
    // Reset power-ups
    Object.keys(powerUps).forEach(key => {
        powerUps[key].count = key === 'doublePoints' ? 2 : (key === 'removeTwo' ? 1 : 1);
        powerUps[key].active = false;
    });
    
    resultContainer.classList.add('hidden');
    quizEl.classList.remove('hidden');
    loadQuestion();
    updatePowerUpUI();
}

// --- INITIALIZATION ---
function initializeApp() {
    // Initialize theme
    initTheme();
    
    // Create power-up UI
    createPowerUpUI();
    
    // Setup keyboard navigation
    setupKeyboardNavigation();
    
    // Load first question
    loadQuestion();
    
    // Add help text for keyboard shortcuts
    const helpText = document.createElement('div');
    helpText.className = 'keyboard-help';
    helpText.innerHTML = '🎮 Keyboard Shortcuts: 1-4 to select, Enter to submit/next, Space to submit';
    document.querySelector('#quiz-container').appendChild(helpText);
}

// --- EVENT LISTENERS ---
submitBtn.addEventListener('click', () => checkAnswer(false));
nextBtn.addEventListener('click', () => {
    currentQuestionIndex++;
    loadQuestion();
});
restartBtn.addEventListener('click', restartQuiz);
themeToggle.addEventListener('click', () => {
    document.body.classList.toggle('light-theme');
    const isLight = document.body.classList.contains('light-theme');
    themeToggle.textContent = isLight ? '🌙' : '🌓';
    localStorage.setItem('quizTheme', isLight ? 'light' : 'dark');
});
shareBtn.addEventListener('click', shareResults);
reviewBtn.addEventListener('click', showReview);
closeReviewBtn.addEventListener('click', () => reviewContainer.classList.add('hidden'));

// Start the application
initializeApp();