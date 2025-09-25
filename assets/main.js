document.getElementById('nextBtn').onclick = ()=>{currentIndex++; showQuestion();};
document.getElementById('prevBtn').onclick = ()=>{if(currentIndex>0){currentIndex--; showQuestion();}};
document.getElementById('modeSelect').onchange = (e)=>{mode=e.target.value; initPool();};
document.getElementById('domainSelect').onchange = (e)=>{initPool();};
initPool();
