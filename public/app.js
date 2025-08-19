let CSRF=null, ME=null, MEMBERS=[];

async function api(path,opt={}) {
  const o={method:opt.method||"GET",headers:{}};
  if(opt.body){o.headers["Content-Type"]="application/json";o.body=JSON.stringify(opt.body);}
  if(!CSRF){const r=await fetch("/api/csrf");CSRF=(await r.json()).csrf;}
  if(o.method!=="GET") o.headers["x-csrf-token"]=CSRF;
  const res=await fetch(path,o);
  if(!res.ok) throw await res.json().catch(()=>({error:"Error"}));
  return res.json();
}

function render() {
  document.getElementById("authPanel").style.display=ME?"none":"block";
  document.getElementById("appPanel").style.display=ME?"block":"none";
  if(ME) {
    document.getElementById("meInfo").textContent=`You are ${ME.name} (${ME.gender})`;
    const list=document.getElementById("members"); list.innerHTML="";
    MEMBERS.forEach(m=>{
      const div=document.createElement("div");
      div.textContent=`${m.name} (${m.gender||"?"}) ${m.partnerName?"- Taken with "+m.partnerName:"- Available"}`;
      if(ME.gender==="girl" && m.gender==="guy" && !ME.partnerId && !m.partnerId){
        const b=document.createElement("button"); b.textContent="Ask out";
        b.onclick=async()=>{
          await api("/api/ask",{method:"POST",body:{toUserId:m.id}});
          alert("Ask sent! Refresh to see status.");
        };
        div.appendChild(b);
      }
      list.appendChild(div);
    });
  }
}

document.getElementById("signupBtn").onclick=async()=>{
  const name=document.getElementById("nameInput").value;
  const code=document.getElementById("codeInput").value;
  const gender=document.getElementById("genderSelect").value;
  try{await api("/api/signup",{method:"POST",body:{name,code,gender}});ME={name,gender};}catch(e){alert(e.error);}
  refresh();
};
document.getElementById("signinBtn").onclick=async()=>{
  const name=document.getElementById("nameInput").value;
  const code=document.getElementById("codeInput").value;
  try{await api("/api/signin",{method:"POST",body:{name,code}});refresh();}catch(e){alert(e.error);}
};

async function refresh(){
  try{ME=(await api("/api/me")).me;}catch{ME=null;}
  try{MEMBERS=(await api("/api/members")).members;}catch{MEMBERS=[];}
  render();
}
refresh();
