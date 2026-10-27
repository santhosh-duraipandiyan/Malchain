(function(){
  var D=window.IOC_DATA, T=D.techniques, PH=D.phases;
  var TById={}; T.forEach(function(x){TById[x.id]=x;});
  var $=function(id){return document.getElementById(id);};
  function esc(s){return String(s==null?"":s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;");}
  function norm(s){return String(s||"").toLowerCase().trim();}
  function attackUrl(id){var b=id.split(".")[0];return "https://attack.mitre.org/techniques/"+b+"/"+(id.indexOf(".")>=0?id.split(".")[1]+"/":"");}
  function cw(code,lang){
    var dots='<span class="dot r"></span><span class="dot"></span><span class="dot"></span>';
    return '<div class="codewrap"><div class="code-top">'+dots+'<span class="lang">'+esc(lang)+'</span>'+
      '<button class="copy-btn" type="button"><svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg><span class="lbl">Copy</span></button>'+
      '</div><pre><code data-lang="'+esc(lang)+'">'+esc(code)+'</code></pre></div>';
  }
  // ---- reverse map a sample onto techniques ----
  function reverseMap(sample){
    var sig=norm(sample.signature), tags=(sample.tags||[]).map(norm);
    var hay=[]; if(sig)hay.push(sig); tags.forEach(function(t){hay.push(t);});
    (sample.yara_rules||[]).forEach(function(y){ if(y&&y.rule_name) hay.push(norm(y.rule_name)); });
    if(sample.delivery) hay.push(norm(sample.delivery));
    var acc={};
    function add(tid,reason,strong){ var a=acc[tid]||(acc[tid]={reasons:[],strong:false}); if(a.reasons.indexOf(reason)<0)a.reasons.push(reason); if(strong)a.strong=true; }
    // precise family / tag seeds (high confidence)
    T.forEach(function(t){
      var sigs=t.sigs.map(norm), tgs=t.tags.map(norm);
      if(sig && sigs.some(function(s){return s===sig||s.indexOf(sig)>=0||sig.indexOf(s)>=0;})) add(t.id,"family <b>"+esc(sample.signature)+"</b>",true);
      tags.forEach(function(tag){
        if(tgs.indexOf(tag)>=0) add(t.id,"tag <code>"+esc(tag)+"</code>",true);
        else if(sigs.some(function(s){return s===tag;})) add(t.id,"family tag <code>"+esc(tag)+"</code>",true);
        else if(/^t\d{4}/.test(tag) && t.attack.some(function(a){return a.id.toLowerCase().indexOf(tag)===0;})) add(t.id,"ATT&CK <code>"+esc(tag.toUpperCase())+"</code>",true);
      });
    });
    // behaviour keyword index: families + capabilities + channels, over family/tags/YARA-rule-names
    var KW=D.keywords||{};
    Object.keys(KW).forEach(function(kw){
      var m;
      if(kw.length<=4){ m=hay.some(function(h){return h===kw || h.split(/[^a-z0-9]+/).indexOf(kw)>=0;}); }
      else { m=hay.some(function(h){return h.indexOf(kw)>=0;}); }
      if(m) KW[kw].forEach(function(tid){ add(tid,"behaviour <code>"+esc(kw)+"</code>",false); });
    });
    var out=Object.keys(acc).map(function(tid){ var t=TById[tid]; return t?{t:t,reasons:acc[tid].reasons,strong:acc[tid].strong}:null; }).filter(Boolean);
    if(!out.length){
      var ft=norm(sample.file_type).split(/[^a-z0-9]+/)[0];
      var base=(D.filetype||{})[ft] || (D.filetype||{})["*"] || [];
      base.forEach(function(tid){ var t=TById[tid]; if(t) out.push({t:t,reasons:["file type <code>"+esc(ft||"exe")+"</code>"],strong:false}); });
    }
    return out;
  }
  // ---- normalize MWB get_info ----
  function normalizeMWB(json){
    if(!json) return null;
    if(json.query_status && json.query_status!=="ok"){ return {error: json.query_status}; }
    var d = json.data ? (Array.isArray(json.data)?json.data[0]:json.data) : json;
    if(!d) return {error:"no_data"};
    return {
      sha256:d.sha256_hash||d.sha256||"", md5:d.md5_hash||d.md5||"", sha1:d.sha1_hash||d.sha1||"",
      file_type:d.file_type||d.file_type_mime||"", file_name:d.file_name||"", file_size:d.file_size||0,
      signature:d.signature||"", tags:d.tags||[], first_seen:d.first_seen||"", last_seen:d.last_seen||"",
      delivery:d.delivery_method||"", yara_rules:d.yara_rules||[], reporter:d.reporter||"",
      imphash:d.imphash||"", ssdeep:d.ssdeep||"", tlsh:d.tlsh||"", mime:d.file_type_mime||"",
      vendor_intel:d.vendor_intel||{}, intelligence:d.intelligence||{}
    };
  }
  function bytes(n){n=+n||0;if(n<1024)return n+" B";if(n<1048576)return (n/1024).toFixed(1)+" KB";return (n/1048576).toFixed(2)+" MB";}
  function chips(arr,cls,fn){return arr.map(fn).join("");}

  // ---- render ----
  function vendorDetections(sample){
    var out=[], intel=sample.intelligence||{};
    if(intel.clamav && intel.clamav.length){ intel.clamav.slice(0,8).forEach(function(x){ out.push({v:"ClamAV",d:x}); }); }
    var vi=sample.vendor_intel||{};
    Object.keys(vi).forEach(function(vendor){
      var val=vi[vendor], item=Array.isArray(val)?val[0]:val;
      if(item==null) return;
      if(typeof item==="string"){ if(item) out.push({v:vendor,d:item}); return; }
      var d=item.detection||item.malware_family||item.family||item.threat_name||item.verdict||item.signature||item.result||item.malware||item.score||item.status;
      out.push({v:vendor,d:(d!=null&&String(d).length)?String(d):"flagged"});
    });
    var seen={},res=[];
    out.forEach(function(o){var k=o.v+"|"+o.d;if(!seen[k]){seen[k]=1;res.push(o);}});
    return res;
  }
  function render(sample){
    var R=$("iocResult");
    if(sample.error){ var e=String(sample.error||"").toLowerCase(); var m=(e.indexOf("not_found")>=0||e.indexOf("no_result")>=0||e.indexOf("hash_not")>=0||e.indexOf("illegal")>=0||e.indexOf("no_data")>=0)?"No record found for that hash on MalwareBazaar.":"Couldn\u2019t retrieve data for that hash right now. Please try again later."; msg(m,"warn"); R.innerHTML=""; return; }
    msg("");
    var mapped=reverseMap(sample);
    var byPhase={}; mapped.forEach(function(o){(byPhase[o.t.code]=byPhase[o.t.code]||[]).push(o);});

    var h='<section class="ioc-head"><div class="ioc-head-top"><span class="pill red">'+(sample.file_type?esc(sample.file_type.toUpperCase()):"SAMPLE")+'</span>'+
      (sample.signature?'<span class="pill ghost">'+esc(sample.signature)+'</span>':'<span class="pill ghost" style="opacity:.6">unattributed</span>')+
      (sample.sha256?'<a class="ioc-open" href="https://bazaar.abuse.ch/sample/'+esc(sample.sha256)+'/" target="_blank" rel="noopener">Open on MalwareBazaar &rarr;</a>':'')+'</div>'+
      '<table class="ioc-meta">'+
      row("SHA-256",sample.sha256?'<code>'+esc(sample.sha256)+'</code>':"—")+
      (sample.sha1?row("SHA-1",'<code>'+esc(sample.sha1)+'</code>'):"")+
      (sample.md5?row("MD5",'<code>'+esc(sample.md5)+'</code>'):"")+
      (sample.imphash?row("imphash",'<code>'+esc(sample.imphash)+'</code>'):"")+
      (sample.ssdeep?row("ssdeep",'<code class="ioc-wrap">'+esc(sample.ssdeep)+'</code>'):"")+
      row("File",(sample.file_name?esc(sample.file_name)+" · ":"")+esc(sample.file_type||sample.mime||"?")+" · "+bytes(sample.file_size))+
      row("Family",sample.signature?esc(sample.signature):"—")+
      (sample.delivery?row("Delivery",esc(sample.delivery)):"")+
      row("Seen",esc(sample.first_seen||"?")+(sample.last_seen?" → "+esc(sample.last_seen):""))+
      (sample.tags&&sample.tags.length?row("Tags",sample.tags.map(function(x){return '<span class="ioc-tag">'+esc(x)+'</span>';}).join("")):"")+
      '</table></section>';

    var banner='<div class="ioc-acc"><b>How to read this.</b> Hashes, pivots, vendor detections and matched YARA are <b>facts about this exact sample</b> — use them to detect it. The framework mapping and per-technique KQL/YARA below are <b>heuristic hunt guidance for the technique category</b>, not sample-specific signatures — expect false positives and tune before alerting.</div>';

    var det=vendorDetections(sample), dv='';
    if(det.length){
      dv='<h2>Detections &amp; verdicts</h2><p class="ioc-sub">Independent detections of this exact sample from MalwareBazaar vendor / sandbox intel — accurate.</p><div class="ioc-verdicts">'+
        det.slice(0,30).map(function(o){return '<div class="ioc-vd"><span class="ioc-vd-v">'+esc(o.v)+'</span><span class="ioc-vd-d">'+esc(o.d)+'</span></div>';}).join("")+'</div>';
    }

    var yr='<h2>Sample-matched YARA</h2>';
    if(sample.yara_rules&&sample.yara_rules.length){
      yr+='<p class="ioc-sub">Community rules (via MalwareBazaar / YARAify) that <b>actually matched this file</b> — the accurate way to detect this sample or family. Distinct from the broad MalChain technique rules further down.</p><div class="ioc-yaralist">';
      sample.yara_rules.forEach(function(y){
        var name=esc(y.rule_name||y.name||"rule");
        var ref=(y.reference&&/^https?:/.test(y.reference))?y.reference:("https://yaraify.abuse.ch/yarahub/rule/"+encodeURIComponent(y.rule_name||""));
        yr+='<div class="ioc-yara"><a href="'+ref+'" target="_blank" rel="noopener"><b>'+name+'</b></a>'+(y.author?'<span class="ioc-ya">by '+esc(y.author)+'</span>':'')+(y.tlp?'<span class="ioc-tlp">TLP:'+esc(y.tlp)+'</span>':'')+(y.description?'<p>'+esc(y.description)+'</p>':'')+'</div>';
      });
      yr+='</div>';
    } else { yr+='<p class="ioc-sub">No YARA matches recorded on MalwareBazaar for this sample — rely on the exact hashes / pivots above for detection.</p>'; }

    var strongN=mapped.filter(function(o){return o.strong;}).length;
    var sub = !mapped.length ? 'No mapping signals in this sample’s metadata.'
              : strongN ? ('Heuristic mapping from this sample’s family and tags — <b>'+mapped.length+'</b> techniques across <b>'+Object.keys(byPhase).length+'</b> phases. Investigative direction, not confirmed behaviour.')
              : ('No family attribution — the <b>'+mapped.length+'</b> techniques below are <b>low-confidence suggestions</b> inferred from file type, delivery and behaviour.');
    var chain='<h2>Framework mapping <span class="ioc-tagpill">heuristic</span></h2><p class="ioc-sub">'+sub+'</p><div class="ioc-chain">';
    PH.forEach(function(p){var n=(byPhase[p.code]||[]).length,on=n>0;chain+='<div class="ioc-ph'+(on?' on':'')+'"><div class="ioc-ph-n">'+p.name+'</div><div class="ioc-ph-c">'+(on?n+(n===1?" technique":" techniques"):"—")+'</div></div>';});
    chain+='</div>';

    var inv="";
    if(!mapped.length){
      inv='<div class="ioc-empty">No framework mapping from this sample’s metadata. Use the exact IOCs and matched YARA above, and explore the <a href="overview.html">framework</a> / <a href="detections.html">detection library</a> for context.</div>';
    } else {
      inv='<h2>Where to look <span class="ioc-tagpill">hunt</span></h2><p class="ioc-sub">Per implicated technique: why it matched, plus a <b>technique-level</b> hunt query and rule. These are behavioural — broad by design, expect false positives, tune before alerting. They are not signatures for this specific sample.</p>';
      PH.forEach(function(p){
        var list=byPhase[p.code]; if(!list) return;
        inv+='<h3 class="ioc-phh">'+p.name+'</h3>';
        list.forEach(function(o){
          var t=o.t;
          inv+='<div class="ioc-tech"><div class="ioc-tech-h"><span class="pill red">'+esc(t.short)+'</span><a href="'+esc(t.url)+'"><b>'+esc(t.title)+'</b></a>'+(o.strong?'':'<span class="ioc-sugg">suggested</span>')+'<span class="ioc-why">matched: '+o.reasons.join(", ")+'</span></div>';
          if(t.attack.length) inv+='<div class="ioc-att">'+t.attack.map(function(a){return '<a class="map-chip att" href="'+attackUrl(a.id)+'" target="_blank" rel="noopener" title="'+esc(a.name)+'"><b>'+esc(a.id)+'</b> '+esc(a.name)+'</a>';}).join("")+'</div>';
          if(t.detection) inv+='<p class="ioc-det">'+esc(t.detection)+'</p>';
          if(t.kql) inv+='<div class="ioc-block"><span class="ioc-block-h">Technique hunt query (KQL) · behavioural</span>'+cw(t.kql,"kql")+'</div>';
          if(t.yara) inv+='<div class="ioc-block"><span class="ioc-block-h">Technique YARA · behavioural, not sample-specific</span>'+cw(t.yara,"yara")+'</div>';
          if(t.mitigation&&t.mitigation.length) inv+='<div class="ioc-mit"><span class="ioc-block-h">Mitigation</span><ul>'+t.mitigation.map(function(m){return "<li>"+esc(m)+"</li>";}).join("")+'</ul></div>';
          inv+='</div>';
        });
      });
    }

    R.innerHTML=h+banner+dv+yr+chain+inv;
    if(window.malchainInitCode) window.malchainInitCode();
    R.scrollIntoView({behavior:"smooth",block:"start"});
  }

  function row(k,v){return '<tr><td class="ioc-k">'+k+'</td><td>'+v+'</td></tr>';}
  function msg(html,kind){var m=$("iocMsg");m.className="ioc-msg"+(kind?" "+kind:"");m.innerHTML=html;}

  // ---- config (Worker URL) + optional local cache ----
  var CFG=window.IOC_CONFIG||{}, CACHE=window.IOC_CACHE||{};
  function workerUrl(){return (CFG.lookupUrl||"").trim();}
  function cachedList(){
    var seen={}, out=[];
    Object.keys(CACHE).forEach(function(k){
      var rec=CACHE[k], d=rec&&rec.data&&rec.data[0]; if(!d)return;
      var h=d.sha256_hash||""; if(h&&!seen[h]){seen[h]=1; out.push({h:h,sig:d.signature||d.file_type||""});}
    });
    return out;
  }
  function renderCached(){
    var box=$("iocCached"); if(!box)return;
    var list=cachedList();
    if(!list.length){ box.innerHTML=""; return; }
    box.innerHTML='<span class="ioc-cached-h">Cached samples ('+list.length+')</span>'+list.map(function(x){return '<button class="ioc-chip" type="button" data-h="'+x.h+'" title="'+esc(x.sig)+'"><code>'+x.h.slice(0,12)+'\u2026</code> '+esc(x.sig)+'</button>';}).join("");
    Array.prototype.forEach.call(box.querySelectorAll(".ioc-chip"),function(b){b.addEventListener("click",function(){$("iocHash").value=b.getAttribute("data-h");lookup();});});
  }
  function renderSetup(){ var el=$("iocSetup"); if(el) el.style.display="none"; }
  // ---- lookup ----
  function lookup(){
    var hash=$("iocHash").value.trim(); if(!hash){msg("Enter a hash first.","warn");return;}
    if(!/^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$/.test(hash)){msg("That doesn\u2019t look like a valid MD5, SHA-1 or SHA-256 hash.","warn");return;}
    var rec=CACHE[hash.toLowerCase()], raw=workerUrl();
    var url = raw ? (/^(https?:|\/)/.test(raw)?raw:(window.SITE_ROOT||"")+raw) : "";
    function fail(){ if(rec){ msg(""); render(normalizeMWB(rec)); } else { msg("Couldn\u2019t complete the lookup right now. Please try again later.","warn"); } }
    if(!url){ fail(); return; }
    msg("Looking up\u2026");
    fetch(url+(url.indexOf("?")>=0?"&":"?")+"hash="+encodeURIComponent(hash),{headers:{"Accept":"application/json"}})
      .then(function(r){ return r.text(); })
      .then(function(txt){ var j=null; try{ j=JSON.parse(txt); }catch(e){} if(j){ msg(""); render(normalizeMWB(j)); } else { fail(); } })
      .catch(function(){ fail(); });
  }
  renderSetup(); renderCached();
  $("iocGo").addEventListener("click",lookup);
  $("iocHash").addEventListener("keydown",function(e){if(e.key==="Enter")lookup();});
})();

