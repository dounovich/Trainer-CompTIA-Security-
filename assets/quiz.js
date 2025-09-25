let pool=[], currentIndex=0, userAnswers={}, mode='exam';

function shuffleArray(a){return a.sort(()=>0.5-Math.random());}

function initPool(){
  userAnswers={}; currentIndex=0;
  let domainFilter = document.getElementById('domainSelect')?.value || 'all';
  pool = QUESTIONS.slice();
  if(mode === 'exam'){
    pool = shuffleArray(pool).slice(0,50);
  } else if(mode === 'training' && domainFilter !== 'all'){
    pool = pool.filter(q => q.domain === domainFilter);
  }
  document.getElementById('quizCard').style.display='block';
  document.getElementById('results').style.display='none';
  showQuestion();
}

function showQuestion(){
  if(currentIndex>=pool.length){ showResults(); return; }
  const q=pool[currentIndex];
  const qText=document.getElementById('questionText');
  const choicesDiv=document.getElementById('choices');
  const expl=document.getElementById('explanation');
  qText.innerText=q.q;
  choicesDiv.innerHTML=''; expl.style.display='none';
  q.choices.forEach((c,i)=>{
    const btn=document.createElement('button');
    btn.className='choice'; btn.innerText=c;
    btn.onclick=()=>{
      userAnswers[q.q]=i;
      Array.from(choicesDiv.children).forEach(ch=>ch.classList.remove('selected'));
      btn.classList.add('selected');
      if(mode==='training'){ expl.style.display='block'; expl.innerText=q.explanation; }
    };
    choicesDiv.appendChild(btn);
  });
  document.getElementById('progress').innerText=`${currentIndex+1} / ${pool.length}`;
}

function showResults(){
  document.getElementById('quizCard').style.display='none';
  const resultsDiv=document.getElementById('results'); resultsDiv.style.display='block';
  let score=0, html='';
  pool.forEach((q,i)=>{
    const userAns=userAnswers[q.q]; const correct=userAns===q.answer;
    if(correct) score++;
    html+=`<div class='resultItem'><p><strong>Q${i+1}: ${q.q}</strong></p>`+
          `<p>Votre réponse: ${userAns!==undefined?q.choices[userAns]:'Aucune'} ${correct?'✅':'❌'}</p>`+
          `<p>Bonne réponse: ${q.choices[q.answer]}</p>`+
          `<p>Explication: ${q.explanation}</p></div><hr>`;
  });
  document.getElementById('scoreSummary').innerHTML=`<h3>Score: ${score} / ${pool.length} (${Math.round(score/pool.length*100)}%)</h3>`;
  document.getElementById('detailedResults').innerHTML=html;
}
