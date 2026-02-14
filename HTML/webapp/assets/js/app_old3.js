            // Risk/Reward Ratio Calculator Logic
            document.addEventListener('DOMContentLoaded', function() {
              var rrForm = document.getElementById('riskRewardForm');
              if (rrForm) {
                rrForm.addEventListener('submit', function(e) {
                  e.preventDefault();
                  var entry = parseFloat(document.getElementById('rr_entry').value);
                  var stop = parseFloat(document.getElementById('rr_stop').value);
                  var target = parseFloat(document.getElementById('rr_target').value);
                  var resultDiv = document.getElementById('risk_reward_result');
                  if (isNaN(entry) || isNaN(stop) || isNaN(target) || entry <= 0 || stop <= 0 || target <= 0) {
                    resultDiv.innerHTML = '<span style="color:red">Please enter valid values for all fields.</span>';
                    return;
                  }
                  var risk = Math.abs(entry - stop);
                  var reward = Math.abs(target - entry);
                  if (risk === 0) {
                    resultDiv.innerHTML = '<span style="color:red">Entry and Stop Loss cannot be the same.</span>';
                    return;
                  }
                  var ratio = reward / risk;
                  resultDiv.innerHTML = `Risk/Reward Ratio: <b>${ratio.toFixed(2)}</b> (Risk: ₹${risk.toFixed(2)}, Reward: ₹${reward.toFixed(2)})`;
                });
              }
            });
            // Volatility/Standard Deviation Calculator Logic
            document.addEventListener('DOMContentLoaded', function() {
              var volForm = document.getElementById('volatilityForm');
              if (volForm) {
                volForm.addEventListener('submit', function(e) {
                  e.preventDefault();
                  var pricesStr = document.getElementById('vol_prices').value;
                  var resultDiv = document.getElementById('volatility_result');
                  if (!pricesStr) {
                    resultDiv.innerHTML = '<span style="color:red">Please enter daily closing prices.</span>';
                    return;
                  }
                  var prices = pricesStr.split(',').map(function(p) { return parseFloat(p.trim()); }).filter(function(p) { return !isNaN(p); });
                  if (prices.length < 2) {
                    resultDiv.innerHTML = '<span style="color:red">Please enter at least two valid prices.</span>';
                    return;
                  }
                  var mean = prices.reduce((a, b) => a + b, 0) / prices.length;
                  var variance = prices.reduce((a, b) => a + Math.pow(b - mean, 2), 0) / (prices.length - 1);
                  var stddev = Math.sqrt(variance);
                  resultDiv.innerHTML = `Standard Deviation (Volatility): <b>${stddev.toFixed(4)}</b>`;
                });
              }
            });
            // Intraday Margin Calculator Logic
            document.addEventListener('DOMContentLoaded', function() {
              var imForm = document.getElementById('intradayMarginForm');
              if (imForm) {
                imForm.addEventListener('submit', function(e) {
                  e.preventDefault();
                  var margin = parseFloat(document.getElementById('im_margin').value);
                  var stockPrice = parseFloat(document.getElementById('im_stock_price').value);
                  var leverage = parseFloat(document.getElementById('im_leverage').value);
                  var resultDiv = document.getElementById('intraday_margin_result');
                  if (isNaN(margin) || isNaN(stockPrice) || isNaN(leverage) || margin <= 0 || stockPrice <= 0 || leverage <= 0) {
                    resultDiv.innerHTML = '<span style="color:red">Please enter valid values for all fields.</span>';
                    return;
                  }
                  var maxBuyQty = Math.floor((margin * leverage) / stockPrice);
                  resultDiv.innerHTML = `You can buy up to <b>${maxBuyQty}</b> shares intraday with the available margin and leverage.`;
                });
              }
            });
            // Covered Call Calculator Logic
            document.addEventListener('DOMContentLoaded', function() {
              var ccForm = document.getElementById('coveredCallForm');
              if (ccForm) {
                ccForm.addEventListener('submit', function(e) {
                  e.preventDefault();
                  var stockPrice = parseFloat(document.getElementById('cc_stock_price').value);
                  var strike = parseFloat(document.getElementById('cc_strike').value);
                  var premium = parseFloat(document.getElementById('cc_premium').value);
                  var lot = parseInt(document.getElementById('cc_lot').value);
                  var resultDiv = document.getElementById('covered_call_result');
                  if (isNaN(stockPrice) || isNaN(strike) || isNaN(premium) || isNaN(lot) || stockPrice <= 0 || strike <= 0 || premium < 0 || lot <= 0) {
                    resultDiv.innerHTML = '<span style="color:red">Please enter valid values for all fields.</span>';
                    return;
                  }
                  var maxProfit = (strike - stockPrice + premium) * lot;
                  var maxLoss = (stockPrice - premium) * lot;
                  var breakeven = stockPrice - premium;
                  resultDiv.innerHTML = `Max Profit: <b>₹${maxProfit.toFixed(2)}</b><br>Max Loss: <b>₹${maxLoss.toFixed(2)}</b><br>Breakeven Price: <b>₹${breakeven.toFixed(2)}</b>`;
                });
              }
            });
            // Options Breakeven Calculator Logic
            document.addEventListener('DOMContentLoaded', function() {
              var obForm = document.getElementById('optionsBreakevenForm');
              if (obForm) {
                obForm.addEventListener('submit', function(e) {
                  e.preventDefault();
                  var type = document.getElementById('ob_type').value;
                  var strike = parseFloat(document.getElementById('ob_strike').value);
                  var premium = parseFloat(document.getElementById('ob_premium').value);
                  var resultDiv = document.getElementById('options_breakeven_result');
                  if (isNaN(strike) || isNaN(premium) || strike <= 0 || premium < 0) {
                    resultDiv.innerHTML = '<span style="color:red">Please enter valid values for all fields.</span>';
                    return;
                  }
                  var breakeven = 0;
                  if (type === 'call') {
                    breakeven = strike + premium;
                    resultDiv.innerHTML = `Breakeven for Call Option: <b>₹${breakeven.toFixed(2)}</b>`;
                  } else {
                    breakeven = strike - premium;
                    resultDiv.innerHTML = `Breakeven for Put Option: <b>₹${breakeven.toFixed(2)}</b>`;
                  }
                });
              }
            });
            // Stock Average Price Calculator Logic
            document.addEventListener('DOMContentLoaded', function() {
              var avgForm = document.getElementById('stockAvgForm');
              if (avgForm) {
                avgForm.addEventListener('submit', function(e) {
                  e.preventDefault();
                  var price1 = parseFloat(document.getElementById('avg_price1').value);
                  var qty1 = parseFloat(document.getElementById('avg_qty1').value);
                  var price2 = parseFloat(document.getElementById('avg_price2').value);
                  var qty2 = parseFloat(document.getElementById('avg_qty2').value);
                  var resultDiv = document.getElementById('stock_avg_result');
                  if (isNaN(price1) || isNaN(qty1) || isNaN(price2) || isNaN(qty2) || price1 <= 0 || qty1 <= 0 || price2 <= 0 || qty2 <= 0) {
                    resultDiv.innerHTML = '<span style="color:red">Please enter valid values for all fields.</span>';
                    return;
                  }
                  var totalCost = (price1 * qty1) + (price2 * qty2);
                  var totalQty = qty1 + qty2;
                  var avgPrice = totalCost / totalQty;
                  resultDiv.innerHTML = `Your average price per share is <b>₹${avgPrice.toFixed(2)}</b> for a total of <b>${totalQty}</b> shares.`;
                });
              }
            });
            // Stock CAGR Calculator Logic
            document.addEventListener('DOMContentLoaded', function() {
              var cagrForm = document.getElementById('stockCAGRForm');
              if (cagrForm) {
                cagrForm.addEventListener('submit', function(e) {
                  e.preventDefault();
                  var initial = parseFloat(document.getElementById('cagr_initial').value);
                  var finalVal = parseFloat(document.getElementById('cagr_final').value);
                  var years = parseFloat(document.getElementById('cagr_years').value);
                  var resultDiv = document.getElementById('stock_cagr_result');
                  if (isNaN(initial) || isNaN(finalVal) || isNaN(years) || initial <= 0 || finalVal <= 0 || years <= 0) {
                    resultDiv.innerHTML = '<span style="color:red">Please enter valid values for all fields.</span>';
                    return;
                  }
                  var cagr = Math.pow(finalVal / initial, 1 / years) - 1;
                  resultDiv.innerHTML = `The CAGR is <b>${(cagr * 100).toFixed(2)}%</b> per year.`;
                });
              }
            });
            // Options Profit/Loss Calculator Logic
            document.addEventListener('DOMContentLoaded', function() {
              var optForm = document.getElementById('optionsPLForm');
              if (optForm) {
                optForm.addEventListener('submit', function(e) {
                  e.preventDefault();
                  var type = document.getElementById('opt_type').value;
                  var side = document.getElementById('opt_side').value;
                  var strike = parseFloat(document.getElementById('opt_strike').value);
                  var premium = parseFloat(document.getElementById('opt_premium').value);
                  var spot = parseFloat(document.getElementById('opt_spot').value);
                  var lot = parseInt(document.getElementById('opt_lot').value);
                  var resultDiv = document.getElementById('options_pl_result');
                  if (isNaN(strike) || isNaN(premium) || isNaN(spot) || isNaN(lot) || lot <= 0) {
                    resultDiv.innerHTML = '<span style="color:red">Please enter valid values for all fields.</span>';
                    return;
                  }
                  var pl = 0;
                  if (type === 'call') {
                    if (side === 'buy') {
                      pl = Math.max(spot - strike, 0) - premium;
                    } else {
                      pl = premium - Math.max(spot - strike, 0);
                    }
                  } else if (type === 'put') {
                    if (side === 'buy') {
                      pl = Math.max(strike - spot, 0) - premium;
                    } else {
                      pl = premium - Math.max(strike - spot, 0);
                    }
                  }
                  var totalPL = pl * lot;
                  var msg = '';
                  if (totalPL > 0) {
                    msg = `Profit: <b>₹${totalPL.toFixed(2)}</b> for this position.`;
                  } else if (totalPL < 0) {
                    msg = `Loss: <b>₹${Math.abs(totalPL).toFixed(2)}</b> for this position.`;
                  } else {
                    msg = 'No profit, no loss for this position.';
                  }
                  resultDiv.innerHTML = msg;
                });
              }
            });
            // Loan Eligibility form
            // Position Sizing Calculator Logic
            document.addEventListener('DOMContentLoaded', function() {
              var psForm = document.getElementById('positionSizingForm');
              if (psForm) {
              psForm.addEventListener('submit', function(e) {
              e.preventDefault();
              var account = parseFloat(document.getElementById('ps_account').value);
              var riskPercent = parseFloat(document.getElementById('ps_risk_percent').value);
              var entry = parseFloat(document.getElementById('ps_entry').value);
              var stop = parseFloat(document.getElementById('ps_stop').value);
              var resultDiv = document.getElementById('position_sizing_result');
              if (isNaN(account) || isNaN(riskPercent) || isNaN(entry) || isNaN(stop) || entry === stop) {
              resultDiv.innerHTML = '<span style="color:red">Please enter valid values for all fields.</span>';
              return;
              }
              var riskAmount = account * (riskPercent / 100);
              var perShareRisk = Math.abs(entry - stop);
              if (perShareRisk === 0) {
              resultDiv.innerHTML = '<span style="color:red">Entry and Stop Loss cannot be the same.</span>';
              return;
              }
              var positionSize = Math.floor(riskAmount / perShareRisk);
              if (positionSize <= 0) {
              resultDiv.innerHTML = '<span style="color:red">Position size is too small for the given risk parameters.</span>';
              return;
              }
              resultDiv.innerHTML = `You can buy <b>${positionSize}</b> shares/contracts to risk no more than <b>₹${riskAmount.toFixed(2)}</b> on this trade.`;
              });
              }
            });
            const loanEligibilityForm = document.getElementById('loanEligibilityForm');
            if(loanEligibilityForm) loanEligibilityForm.onsubmit = function(e){ e.preventDefault(); loanEligibilityCalc(); };
          // Loan Eligibility Calculator Logic
          function loanEligibilityCalc() {
            const income = parseFloat(document.querySelector('#loanEligibilityForm #le_income').value) || 0;
            const existingEmi = parseFloat(document.querySelector('#loanEligibilityForm #le_existing_emi').value) || 0;
            const tenure = parseFloat(document.querySelector('#loanEligibilityForm #le_tenure').value) || 0;
            const rate = parseFloat(document.querySelector('#loanEligibilityForm #le_rate').value) || 0;
            // Assume max 50% of net income can go to all EMIs
            const maxEmi = income * 0.5 - existingEmi;
            const months = tenure * 12;
            const r = rate / 100 / 12;
            let eligibleLoan = 0;
            if (r > 0 && months > 0) {
              eligibleLoan = maxEmi * ( (Math.pow(1 + r, months) - 1) / (r * Math.pow(1 + r, months)) );
            }
            document.querySelector('#loan_eligibility_tab #loan_eligibility_result').innerText =
              (eligibleLoan > 0
                ? `Based on your income and existing EMIs, you may be eligible for a loan of up to ₹${eligibleLoan.toLocaleString(undefined, {maximumFractionDigits:0})}.`
                : 'Sorry, you are not eligible for a loan with the current details.');
          }
          // FD form
          const fdForm = document.getElementById('fdForm');
          if(fdForm) fdForm.onsubmit = function(e){ e.preventDefault(); fdCalc(); };
        // FD Calculator Logic
        function fdCalc() {
          const principal = parseFloat(document.querySelector('#fdForm #fd_principal').value) || 0;
          const years = parseFloat(document.querySelector('#fdForm #fd_years').value) || 0;
          const rate = parseFloat(document.querySelector('#fdForm #fd_rate').value) || 0;
          // Quarterly compounding
          const n = 4;
          const maturity = principal * Math.pow(1 + (rate/100)/n, n*years);
          const interest = maturity - principal;
          document.querySelector('#fd_tab #fd_result').innerText =
            `If you invest ₹${principal.toLocaleString()} in a fixed deposit for ${years} years at ${rate}% interest, you will get about ₹${maturity.toLocaleString(undefined, {maximumFractionDigits:0})} at maturity.\n` +
            `Your interest earned will be ₹${interest.toLocaleString(undefined, {maximumFractionDigits:0})}.`;
        }
        // RD form
        const rdForm = document.getElementById('rdForm');
        if(rdForm) rdForm.onsubmit = function(e){ e.preventDefault(); rdCalc(); };
      // RD Calculator Logic
      function rdCalc() {
        const monthly = parseFloat(document.querySelector('#rdForm #rd_monthly').value) || 0;
        const years = parseFloat(document.querySelector('#rdForm #rd_years').value) || 0;
        const rate = parseFloat(document.querySelector('#rdForm #rd_rate').value) || 0;
        const months = years * 12;
        const r = rate / 100 / 4; // Quarterly compounding
        // Formula: M * [ (1+r)^n -1 ] / (1 - (1+r)^(-1/3))
        let maturity = 0;
        if (r > 0) maturity = monthly * ((Math.pow(1 + r, months / 3) - 1) / (1 - Math.pow(1 + r, -1/3)));
        else maturity = monthly * months;
        const invested = monthly * months;
        const interest = maturity - invested;
        document.querySelector('#rd_tab #rd_result').innerText =
          `By depositing ₹${monthly.toLocaleString()} every month for ${years} years at ${rate}% interest, you will receive about ₹${maturity.toLocaleString(undefined, {maximumFractionDigits:0})} at maturity.\n` +
          `You will have invested ₹${invested.toLocaleString(undefined, {maximumFractionDigits:0})}, and earned interest of ₹${interest.toLocaleString(undefined, {maximumFractionDigits:0})}.`;
      }
      // EMI vs SIP form
      const emivsipForm = document.getElementById('emivsipForm');
      if(emivsipForm) emivsipForm.onsubmit = function(e){ e.preventDefault(); emivsipCalc(); };
    // EMI vs SIP Calculator Logic
    function emivsipCalc() {
      const loan = parseFloat(document.querySelector('#emivsipForm #emivsip_loan').value) || 0;
      const years = parseFloat(document.querySelector('#emivsipForm #emivsip_years').value) || 0;
      const emiRate = parseFloat(document.querySelector('#emivsipForm #emivsip_emi_rate').value) || 0;
      const sip = parseFloat(document.querySelector('#emivsipForm #emivsip_sip').value) || 0;
      const sipRate = parseFloat(document.querySelector('#emivsipForm #emivsip_sip_rate').value) || 0;
      const months = years * 12;
      const emiR = emiRate / 100 / 12;
      const sipR = sipRate / 100 / 12;
      // EMI calculation
      let emi = 0;
      if (emiR > 0) emi = (loan * emiR * Math.pow(1 + emiR, months)) / (Math.pow(1 + emiR, months) - 1);
      else emi = loan / months;
      const totalEmiPaid = emi * months;
      // SIP calculation
      let sipFV = 0;
      if (sipR > 0) sipFV = sip * ((Math.pow(1 + sipR, months) - 1) / sipR) * (1 + sipR);
      else sipFV = sip * months;
      // Result
      document.querySelector('#emivsip_tab #emivsip_result').innerText =
        `If you take a loan of ₹${loan.toLocaleString()} for ${years} years at ${emiRate}% interest, your EMI will be about ₹${emi.toLocaleString(undefined, {maximumFractionDigits:0})} per month, and you'll pay a total of ₹${totalEmiPaid.toLocaleString(undefined, {maximumFractionDigits:0})}.\n` +
        `If you invest ₹${sip.toLocaleString()} per month in a SIP at ${sipRate}% return, you could have about ₹${sipFV.toLocaleString(undefined, {maximumFractionDigits:0})} at the end of ${years} years.`;
    }
    // Crorepati form
    const crorepatiForm = document.getElementById('crorepatiForm');
    if(crorepatiForm) crorepatiForm.onsubmit = function(e){ e.preventDefault(); crorepatiCalc(); };
  // Crorepati Calculator Logic
  function crorepatiCalc() {
    const target = parseFloat(document.querySelector('#crorepatiForm #crore_target').value) || 0;
    const sip = parseFloat(document.querySelector('#crorepatiForm #crore_sip').value) || 0;
    const rate = parseFloat(document.querySelector('#crorepatiForm #crore_return').value) || 0;
    const r = rate/100/12;
    let months = 0;
    if (sip > 0 && r > 0 && target > 0) {
      // n = ln((FV*r/sip)+1)/ln(1+r)
      months = Math.log((target*r/sip)+1)/Math.log(1+r);
    } else if (sip > 0 && target > 0) {
      months = target/sip;
    }
    const years = months/12;
    document.querySelector('#crorepati_tab #crorepati_result').innerText =
      (months > 0
        ? `If you invest ₹${sip.toLocaleString()} per month at ${rate}% annual return, you can reach your goal of ₹${target.toLocaleString()} in about ${years.toFixed(1)} years (${Math.ceil(months)} months).`
        : 'Please enter valid values.');
  }
  // Net Worth form
  const networthForm = document.getElementById('networthForm');
  if(networthForm) networthForm.onsubmit = function(e){ e.preventDefault(); networthCalc(); };
// Net Worth Calculator Logic
function networthCalc() {
  const assets = parseFloat(document.querySelector('#networthForm #nw_assets').value) || 0;
  const liabilities = parseFloat(document.querySelector('#networthForm #nw_liabilities').value) || 0;
  const networth = assets - liabilities;
  document.querySelector('#networth_tab #networth_result').innerText =
    `Your net worth is ₹${networth.toLocaleString()}. This is the difference between your total assets and liabilities.`;
}
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
  document.querySelector('#sip_tab #sip_result').innerText =
    `If you invest ₹${p.toLocaleString()} per month for ${n} years at ${r}% annual return, you could have about ₹${parseFloat(fv).toLocaleString(undefined, {maximumFractionDigits:0})} at the end.`;
  const invested = p*months;
  document.querySelector('#sip_tab #sip_detail').innerText =
    `You will have invested a total of ₹${parseFloat(invested).toLocaleString(undefined, {maximumFractionDigits:0})}.`;
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
  document.querySelector('#goal_tab #goal_result').innerText =
    `To reach your goal of ₹${goal.toLocaleString()} in ${years} years at ${rate}% return, you need to invest about ₹${sip.toLocaleString(undefined, {maximumFractionDigits:0})} per month.`;
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
  document.querySelector('#lumpsum_tab #lump_result').innerText =
    `If you invest ₹${amt.toLocaleString()} as a lumpsum for ${years} years at ${r}% return, you could have about ₹${parseFloat(fv).toLocaleString(undefined, {maximumFractionDigits:0})} at the end.`;
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
  document.querySelector('#lumpsumsip_tab #ls_result').innerText =
    `If you invest ₹${lump.toLocaleString()} as a lumpsum and ₹${sip.toLocaleString()} per month for ${n} years at ${r}% return, you could have about ₹${parseFloat(totalFv).toLocaleString(undefined, {maximumFractionDigits:0})} at the end.`;
  renderLsChart({labels, values});
}
// Budget tracker
document.addEventListener('DOMContentLoaded', function(){
    // Open correct tab if hash is present
    var hash = window.location.hash;
    if (hash && document.getElementById(hash.substring(1))) {
      showTab(hash.substring(1));
    } else {
      showTab('sip_tab');
    }

    // Retirement Planner form
    const retirementForm = document.getElementById('retirementForm');
    if(retirementForm) retirementForm.onsubmit = function(e){ e.preventDefault(); retirementCalc(); };
  // Retirement Planner Calculator Logic
  function retirementCalc() {
    // Get form values
    const age = parseFloat(document.querySelector('#retirementForm #ret_age').value) || 0;
    const retireAge = parseFloat(document.querySelector('#retirementForm #ret_retire_age').value) || 0;
    const currentSavings = parseFloat(document.querySelector('#retirementForm #ret_savings').value) || 0;
    const monthlyInvestment = parseFloat(document.querySelector('#retirementForm #ret_investment').value) || 0;
    const annualReturn = parseFloat(document.querySelector('#retirementForm #ret_return').value) || 0;
    const monthlyExpense = parseFloat(document.querySelector('#retirementForm #ret_expense').value) || 0;
    const yearsRetired = parseFloat(document.querySelector('#retirementForm #ret_years_retired').value) || 0;
    const inflation = parseFloat(document.querySelector('#retirementForm #ret_inflation').value) || 0;

    const yearsToRetire = retireAge - age;
    const monthsToRetire = yearsToRetire * 12;
    const r = annualReturn / 100 / 12;
    // Future value of current savings
    const fvCurrent = currentSavings * Math.pow(1 + r, monthsToRetire);
    // Future value of monthly investments
    const fvInvest = monthlyInvestment * ((Math.pow(1 + r, monthsToRetire) - 1) / r) * (1 + r);
    const totalAtRetirement = fvCurrent + fvInvest;

    // Inflate monthly expense to retirement
    const inflatedExpense = monthlyExpense * Math.pow(1 + inflation / 100, yearsToRetire);
    // Calculate required corpus at retirement (PV of annuity)
    const rRet = annualReturn / 100 / 12;
    const nRet = yearsRetired * 12;
    const requiredCorpus = rRet > 0 ? inflatedExpense * (1 - Math.pow(1 + rRet, -nRet)) / rRet : inflatedExpense * nRet;

    // Display results
    document.querySelector('#retirement_tab #retirement_result').innerText =
      `To maintain your lifestyle in retirement, you may need about ₹${Math.round(requiredCorpus).toLocaleString()} as a retirement corpus.`;
    document.querySelector('#retirement_tab #retirement_detail').innerText =
      `At your current pace, you could have about ₹${Math.round(totalAtRetirement).toLocaleString()} by retirement. ` +
      (totalAtRetirement >= requiredCorpus ? 'You are on track for your goal!' : 'You may need to invest more to reach your target.');
  }
  // Contact form AJAX handler with validation
    const contactForm = document.getElementById('contactForm');
    if(contactForm) contactForm.onsubmit = async function(e) {
      e.preventDefault();
      const name = document.getElementById('contact_name').value;
      const email = document.getElementById('contact_email').value;
      const phone = document.getElementById('contact_phone').value;
      const message = document.getElementById('contact_message').value;
      const statusDiv = document.getElementById('contact_status');


      // Name validation: at least 3 characters
      if(!name || name.trim().length < 3) {
        statusDiv.textContent = 'Name must be at least 3 characters.';
        return;
      }
      // Phone validation: must be exactly 10 digits if provided
      if(phone) {
        if(!/^\d{10}$/.test(phone)) {
          statusDiv.textContent = 'Mobile number must be exactly 10 digits.';
          return;
        }
      }
      // Email validation: basic regex
      if(!/^\S+@\S+\.\S+$/.test(email)) {
        statusDiv.textContent = 'Not a valid email address.';
        return;
      }

      statusDiv.textContent = 'Sending...';
      try {
        const res = await fetch((window.location.origin + '/send-email'), {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ name, email, phone, message })
        });
        const data = await res.json();
        if(data.success) {
          statusDiv.textContent = 'Message sent successfully!';
          contactForm.reset();
        } else {
          statusDiv.textContent = 'Failed to send: ' + data.message;
        }
      } catch (err) {
        statusDiv.textContent = 'Error sending message.';
      }
    };
  // FIRE form
  const fireForm = document.getElementById('fireForm');
  if(fireForm) fireForm.onsubmit = function(e){ e.preventDefault(); fireCalc(); };
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

// FIRE Calculator Logic
function fireCalc() {
  // Get form values (fix input IDs to match HTML)
  const annualExpense = parseFloat(document.querySelector('#fireForm #fire_expenses').value) || 0;
  const withdrawalRate = parseFloat(document.querySelector('#fireForm #fire_withdrawal').value) || 4; // default 4%
  const currentSavings = parseFloat(document.querySelector('#fireForm #fire_savings').value) || 0;
  const annualInvestment = parseFloat(document.querySelector('#fireForm #fire_annual_saving').value) || 0;
  const annualReturn = parseFloat(document.querySelector('#fireForm #fire_return').value) || 0;
  // Calculate FIRE number
  const fireNumber = withdrawalRate > 0 ? (annualExpense * 100) / withdrawalRate : 0;
  // Years to FIRE calculation (future value of a series)
  let years = 0;
  if (annualReturn > 0 && annualInvestment > 0) {
    const r = annualReturn / 100;
    // Solve for n: FV = PV*(1+r)^n + PMT*(((1+r)^n - 1)/r)
    // FV = fireNumber, PV = currentSavings, PMT = annualInvestment
    // Use logarithms to solve for n
    const PV = currentSavings;
    const PMT = annualInvestment;
    const FV = fireNumber;
    const rate = r;
    if (rate > 0) {
      // n = ln((FV*rate + PMT)/(PV*rate + PMT)) / ln(1+rate)
      const numerator = Math.log((FV * rate + PMT) / (PV * rate + PMT));
      const denominator = Math.log(1 + rate);
      years = numerator / denominator;
      if (years < 0 || isNaN(years) || !isFinite(years)) years = 0;
    }
  }
  // Display results
  document.querySelector('#fire_tab #fire_result').innerText =
    `To retire early and cover your annual expenses of ₹${annualExpense.toLocaleString()}, you would need about ₹${fireNumber.toLocaleString(undefined, {maximumFractionDigits: 0})} (your FIRE number).`;
  let yearsDiv = document.querySelector('#fire_tab #fire_years');
  if (!yearsDiv) {
    yearsDiv = document.createElement('div');
    yearsDiv.id = 'fire_years';
    yearsDiv.style.marginTop = '6px';
    yearsDiv.style.color = '#6b5f82';
    document.querySelector('#fire_tab .card').appendChild(yearsDiv);
  }
  yearsDiv.innerText = years > 0 ? ('Estimated Years to FIRE: ' + years.toFixed(1)) : '';
}

