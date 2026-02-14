function renderSipChart(data) {
  const ctx = document.getElementById('sip_chart').getContext('2d');
  if(sipChart) sipChart.destroy();
  sipChart = new Chart(ctx, {
    type: 'line',
    data: {
      labels: data.labels,
      datasets: [
        { label: 'Investment Value', data: data.values, borderColor: '#6A1B9A', backgroundColor: 'rgba(106,27,154,0.1)', fill: true }
      ]
    },
    options: { plugins: { legend: { display: false } }, scales: { x: { title: { display: true, text: 'Month' } }, y: { title: { display: true, text: 'Value (₹)' } } } }
  });
}
function sipCalc() {
  const p = parseFloat(document.querySelector('#sipForm #sip_p').value)||0;
  const r = parseFloat(document.querySelector('#sipForm #sip_r').value)||0;
  const n = parseFloat(document.querySelector('#sipForm #sip_n').value)||0;
  const rn = r/100/12;
  const months = n*12;
  let fv = 0;
  let values = [], labels = [];
  for(let i=1;i<=months;i++){
    let v = rn===0 ? p*i : p*((Math.pow(1+rn,i)-1)/rn)*(1+rn);
    values.push(v.toFixed(2));
    labels.push(i);
  }
  if(rn===0) fv = p*months;
  else fv = p * ((Math.pow(1+rn, months)-1)/rn) * (1+rn);
  document.querySelector('#sip_tab #sip_result').innerText = 'Future Value: ₹' + fv.toFixed(2);
  const invested = p*months;
  document.querySelector('#sip_tab #sip_detail').innerText = 'Total Invested: ₹'+invested.toFixed(2);
  renderSipChart({labels, values});
}
function renderGoalChart(data) {
  const ctx = document.getElementById('goal_chart').getContext('2d');
  if(goalChart) goalChart.destroy();
  goalChart = new Chart(ctx, {
    type: 'line',
    data: {
      labels: data.labels,
      datasets: [
        { label: 'Accumulated Value', data: data.values, borderColor: '#8E24AA', backgroundColor: 'rgba(142,36,170,0.1)', fill: true }
      ]
    },
    options: { plugins: { legend: { display: false } }, scales: { x: { title: { display: true, text: 'Month' } }, y: { title: { display: true, text: 'Value (₹)' } } } }
  });
}
function goalCalc(){
  const goal = parseFloat(document.querySelector('#goalForm #goal_amount').value)||0;
  const rate = parseFloat(document.querySelector('#goalForm #goal_r').value)||0;
  const years = parseFloat(document.querySelector('#goalForm #goal_n').value)||0;
  const rn = rate/100/12;
  const months = years*12;
  let sip = 0;
  let values = [], labels = [];
  for(let i=1;i<=months;i++){
    let v = rn===0 ? (goal/months)*i : (goal*rn)/(Math.pow(1+rn,months)-1)*((Math.pow(1+rn,i)-1)/rn)*(1+rn);
    values.push(v.toFixed(2));
    labels.push(i);
  }
  if(rn===0) sip = goal/months;
  else sip = (goal*rn)/(Math.pow(1+rn,months)-1);
  document.querySelector('#goal_tab #goal_result').innerText = 'Required SIP: ₹' + sip.toFixed(2) + ' /month';
  renderGoalChart({labels, values});
}
function renderEmiChart(data) {
  const ctx = document.getElementById('emi_chart').getContext('2d');
  if(emiChart) emiChart.destroy();
  emiChart = new Chart(ctx, {
    type: 'bar',
    data: {
      labels: ['Principal', 'Interest'],
      datasets: [
        { label: 'Amount (₹)', data: data, backgroundColor: ['#5E35B1','#D7CFEA'] }
      ]
    },
    options: { plugins: { legend: { display: false } } }
  });
}
function emiCalc(){
  const loan = parseFloat(document.querySelector('#emiForm #emi_loan').value)||0;
  const rate = parseFloat(document.querySelector('#emiForm #emi_r').value)||0;
  const years = parseFloat(document.querySelector('#emiForm #emi_n').value)||0;
  const rn = rate/100/12;
  const months = years*12;
  let emi = 0;
  if(rn===0) emi = loan/months;
  else emi = (loan*rn*Math.pow(1+rn,months))/(Math.pow(1+rn,months)-1);
  document.querySelector('#emi_tab #emi_result').innerText = 'EMI: ₹' + emi.toFixed(2);
  let total = emi*months;
  let interest = total-loan;
  renderEmiChart([loan, interest]);
}
// Budget & Goal Tracker chart
function renderBudgetChart(savings, goal) {
  const ctx = document.getElementById('budget_chart').getContext('2d');
  if(budgetChart) budgetChart.destroy();
  budgetChart = new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels: ['Savings', 'Remaining to Goal'],
      datasets: [{ data: [savings, Math.max(0, goal-savings)], backgroundColor: ['#4CAF50','#D7CFEA'] }]
    },
    options: { plugins: { legend: { display: true } } }
  });
}
let lumpChart, lsChart;
function renderLumpChart(data) {
  const ctx = document.getElementById('lump_chart').getContext('2d');
  if(lumpChart) lumpChart.destroy();
  lumpChart = new Chart(ctx, {
    type: 'line',
    data: {
      labels: data.labels,
      datasets: [
        { label: 'Investment Value', data: data.values, borderColor: '#3F0071', backgroundColor: 'rgba(63,0,113,0.1)', fill: true }
      ]
    },
    options: { plugins: { legend: { display: false } }, scales: { x: { title: { display: true, text: 'Year' } }, y: { title: { display: true, text: 'Value (₹)' } } } }
  });
}
function lumpCalc() {
  const amt = parseFloat(document.querySelector('#lumpsumForm #lump_amt').value)||0;
  const r = parseFloat(document.querySelector('#lumpsumForm #lump_r').value)||0;
  const n = parseFloat(document.querySelector('#lumpsumForm #lump_n').value)||0;
  const years = n;
  let values = [], labels = [];
  for(let i=1;i<=years;i++){
    let v = amt * Math.pow(1 + r/100, i);
    values.push(v.toFixed(2));
    labels.push(i);
  }
  let fv = amt * Math.pow(1 + r/100, years);
  document.querySelector('#lumpsum_tab #lump_result').innerText = 'Future Value: ₹' + fv.toFixed(2);
  renderLumpChart({labels, values});
}
function renderLsChart(data) {
  const ctx = document.getElementById('ls_chart').getContext('2d');
  if(lsChart) lsChart.destroy();
  lsChart = new Chart(ctx, {
    type: 'line',
    data: {
      labels: data.labels,
      datasets: [
        { label: 'Total Value', data: data.values, borderColor: '#5E35B1', backgroundColor: 'rgba(94,53,177,0.1)', fill: true }
      ]
    },
    options: { plugins: { legend: { display: false } }, scales: { x: { title: { display: true, text: 'Month' } }, y: { title: { display: true, text: 'Value (₹)' } } } }
  });
}
function lsCalc() {
  const lump = parseFloat(document.querySelector('#lumpsumSipForm #ls_lump_amt').value)||0;
  const sip = parseFloat(document.querySelector('#lumpsumSipForm #ls_sip_amt').value)||0;
  const r = parseFloat(document.querySelector('#lumpsumSipForm #ls_r').value)||0;
  const n = parseFloat(document.querySelector('#lumpsumSipForm #ls_n').value)||0;
  const months = n*12;
  const rn = r/100/12;
  let values = [], labels = [];
  for(let i=1;i<=months;i++){
    let lumpVal = lump * Math.pow(1+rn,i);
    let sipVal = rn===0 ? sip*i : sip*((Math.pow(1+rn,i)-1)/rn)*(1+rn);
    values.push((lumpVal+sipVal).toFixed(2));
    labels.push(i);
  }
  let lumpFv = lump * Math.pow(1+rn,months);
  let sipFv = rn===0 ? sip*months : sip*((Math.pow(1+rn,months)-1)/rn)*(1+rn);
  let totalFv = lumpFv + sipFv;
  document.querySelector('#lumpsumsip_tab #ls_result').innerText = 'Future Value: ₹' + totalFv.toFixed(2);
  renderLsChart({labels, values});
}
// Budget tracker
document.addEventListener('DOMContentLoaded', function(){
  // SIP form
  const sipForm = document.getElementById('sipForm');
  if(sipForm) sipForm.onsubmit = function(e){ e.preventDefault(); sipCalc(); };
  // Goal form
  const goalForm = document.getElementById('goalForm');
  if(goalForm) goalForm.onsubmit = function(e){ e.preventDefault(); goalCalc(); };
  // EMI form
  const emiForm = document.getElementById('emiForm');
  if(emiForm) emiForm.onsubmit = function(e){ e.preventDefault(); emiCalc(); };
  // Budget form
  const budgetForm = document.getElementById('budgetForm');
  if(budgetForm) budgetForm.onsubmit = function(e){ e.preventDefault();
    var income = parseFloat(document.querySelector('#budgetForm #income').value) || 0;
    var expenses = parseFloat(document.querySelector('#budgetForm #expenses').value) || 0;
    var goal = parseFloat(document.querySelector('#budgetForm #goal').value) || 0;
    var savings = income - expenses;
    var percent = goal ? Math.min(100, Math.round((savings/goal)*100)) : 0;
    var summaryText = `Income: ₹${income.toLocaleString()}<br>Expenses: ₹${expenses.toLocaleString()}<br>Savings: ₹${savings.toLocaleString()}<br>Goal: ₹${goal.toLocaleString()}<br>Progress: ${percent}%`;
    document.querySelector('#budget_tab #summaryText').innerHTML = summaryText;
    document.querySelector('#budget_tab #progress').style.width = percent + '%';
    document.querySelector('#budget_tab #summary').style.display = 'block';
    renderBudgetChart(savings, goal);
  };
  // Lumpsum form
  const lumpForm = document.getElementById('lumpsumForm');
  if(lumpForm) lumpForm.onsubmit = function(e){ e.preventDefault(); lumpCalc(); };
  // Lumpsum+SIP form
  const lsForm = document.getElementById('lumpsumSipForm');
  if(lsForm) lsForm.onsubmit = function(e){ e.preventDefault(); lsCalc(); };
});
// Buy vs Rent chart placeholder (can be expanded for more analysis)
// ...existing buy vs rent logic remains, chart can be added as needed...
