let currentQuestionIndex = 0;
let currentQuestions = [];
let userAnswers = [];

function shuffleArray(array){ return array.sort(()=>Math.random()-0.5); }

function allAnswered(){
  // true if no undefined in the array and length matches questions count
  return userAnswers.length === currentQuestions.length && userAnswers.every(v => v !== undefined);
}

function updateSubmitButton(){
  const submitBtn = document.getElementById('submit-btn');
  submitBtn.disabled = !allAnswered();
}

function updateProgress(){
  const pc = document.getElementById('progress-counter');
  pc.textContent = 'Question ' + (currentQuestionIndex+1) + ' / ' + currentQuestions.length;
}

function renderQuestion(question, container, mode){
  container.innerHTML = '';
  const card = document.createElement('div');
  card.className = 'card';

  const qElem = document.createElement('div');
  qElem.className = 'q';
  qElem.textContent = question.q;
  card.appendChild(qElem);

  const answersDiv = document.createElement('div');
  answersDiv.className = 'choices';

  question.choices.forEach((choice, i) => {
    const opt = document.createElement('div');
    opt.className = 'choice';
    opt.textContent = choice;
    opt.dataset.index = i;

    if (userAnswers[currentQuestionIndex] === i) {
      opt.classList.add('selected');
    }

    opt.addEventListener('click', () => {
      userAnswers[currentQuestionIndex] = i;
      answersDiv.querySelectorAll('.choice').forEach(c => c.classList.remove('selected','correct','wrong'));
      opt.classList.add('selected');

      if (mode === 'training') {
        if (i === question.answer) {
          opt.classList.add('correct');
        } else {
          opt.classList.add('wrong');
          // highlight correct
          const correctEl = answersDiv.querySelector('.choice[data-index="'+question.answer+'"]');
          if (correctEl) correctEl.classList.add('correct');
        }
      }

      updateSubmitButton();
    });

    answersDiv.appendChild(opt);
  });

  card.appendChild(answersDiv);
  container.innerHTML = '';
  container.appendChild(card);

  updateProgress();
  updateSubmitButton();

  // Update prev/next buttons enabled state
  const prevBtn = document.getElementById('prev-btn');
  const nextBtn = document.getElementById('next-btn');
  prevBtn.disabled = currentQuestionIndex === 0;
  nextBtn.disabled = currentQuestionIndex === currentQuestions.length - 1;
}

function showResults(container){
  container.innerHTML = '';
  let score = 0;

  const summary = document.createElement('div');
  summary.className = 'card';

  currentQuestions.forEach((q,i) => { if (userAnswers[i] === q.answer) score++; });

  summary.innerHTML = '<b>Score final : ' + score + ' / ' + currentQuestions.length + ' (' + (score/currentQuestions.length*100).toFixed(1) + '%)</b>';
  container.appendChild(summary);

  currentQuestions.forEach((q,i) => {
    const card = document.createElement('div');
    card.className = 'card';
    const qElem = document.createElement('div');
    qElem.className = 'q';
    qElem.textContent = (i+1)+'. ' + q.q;
    card.appendChild(qElem);

    q.choices.forEach((c,j) => {
      const el = document.createElement('div');
      el.className = 'choice';
      el.textContent = c;
      if (j === q.answer) el.classList.add('correct');
      if (userAnswers[i] === j && j !== q.answer) el.classList.add('wrong');
      card.appendChild(el);
    });

    container.appendChild(card);
  });
}

function startQuiz(mode, domain){
  // Prepare pool
  const all = (domain === 'all') ? QUESTIONS.slice() : QUESTIONS.filter(q => q.domain === domain);
  currentQuestions = (mode === 'exam') ? shuffleArray(all).slice(0, Math.min(50, all.length)) : all;

  // Reset state
  currentQuestionIndex = 0;
  userAnswers = new Array(currentQuestions.length).fill(undefined);

  const container = document.getElementById('quiz-container');
  document.getElementById('quiz-footer').style.display = 'flex';

  // Wire nav buttons
  document.getElementById('prev-btn').onclick = () => {
    if (currentQuestionIndex > 0) {
      currentQuestionIndex--;
      renderQuestion(currentQuestions[currentQuestionIndex], container, mode);
    }
  };
  document.getElementById('next-btn').onclick = () => {
    if (currentQuestionIndex < currentQuestions.length - 1) {
      currentQuestionIndex++;
      renderQuestion(currentQuestions[currentQuestionIndex], container, mode);
    }
  };
  document.getElementById('submit-btn').onclick = () => {
    if (!allAnswered()) {
      alert('Veuillez répondre à toutes les questions avant de valider.');
      return;
    }
    showResults(container);
    document.getElementById('quiz-footer').style.display = 'none';
  };

  // First render
  renderQuestion(currentQuestions[currentQuestionIndex], container, mode);
}
