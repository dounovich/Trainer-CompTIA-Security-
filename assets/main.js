document.addEventListener('DOMContentLoaded', () => {
  const modeSelect = document.getElementById('mode');
  const domainSelect = document.getElementById('domain');

  function updateQuiz(){
    startQuiz(modeSelect.value, domainSelect.value);
  }

  modeSelect.addEventListener('change', updateQuiz);
  domainSelect.addEventListener('change', updateQuiz);

  updateQuiz();
});
