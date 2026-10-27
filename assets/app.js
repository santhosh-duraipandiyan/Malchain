(function(){
  "use strict";

  /* ---------- keyword sets ---------- */
  var KQL_KW = new Set(("let where project project-away extend summarize join union on kind by count dcount sum make_set make_list "+
    "ago bin now datetime timespan has has_any has_all hasprefix hassuffix contains startswith endswith matches regex in and or not "+
    "between order sort asc desc take limit top distinct render parse split strlen tostring tolong toint isempty isnotempty "+
    "coalesce iff case min max avg dcountif countif leftouter inner innerunique fullouter anti semi").split(/\s+/));
  var YARA_KW = new Set(("rule meta strings condition and or not of them all any them at in for entrypoint filesize "+
    "ascii wide nocase fullword base64 base64wide xor private global import include "+
    "uint8 uint16 uint32 int8 int16 int32 uint16be uint32be true false").split(/\s+/));

  function esc(s){return s.replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");}

  function highlight(code, lang){
    var kw = lang==="yara"?YARA_KW:KQL_KW;
    var out="", i=0, n=code.length, guard=n*8+100;
    function isId(c){return c && /[A-Za-z0-9_$]/.test(c);}
    while(i<n){
      if(--guard<0){out+=esc(code.slice(i));break;}
      var c=code[i], c2=code[i+1];
      // block comment
      if(c==="/"&&c2==="*"){var j=code.indexOf("*/",i+2);j=j<0?n:j+2;out+='<span class="tk-cmt">'+esc(code.slice(i,j))+'</span>';i=j;continue;}
      // line comment
      if(c==="/"&&c2==="/"){var j2=code.indexOf("\n",i);j2=j2<0?n:j2;out+='<span class="tk-cmt">'+esc(code.slice(i,j2))+'</span>';i=j2;continue;}
      // string
      if(c==='"'){var j3=i+1;while(j3<n){if(code[j3]==="\\"){j3+=2;continue;}if(code[j3]==='"'){j3++;break;}j3++;}out+='<span class="tk-str">'+esc(code.slice(i,j3))+'</span>';i=j3;continue;}
      // hex byte pattern { AB CD } inside yara -> treat as string-ish
      // number / hex
      if(/[0-9]/.test(c) && !isId(code[i-1])){var j4=i;while(j4<n&&/[0-9a-fA-FxX.]/.test(code[j4]))j4++;out+='<span class="tk-num">'+esc(code.slice(i,j4))+'</span>';i=j4;continue;}
      // identifier / keyword
      if(/[A-Za-z_$]/.test(c)){var j5=i;while(j5<n&&/[A-Za-z0-9_$]/.test(code[j5]))j5++;var w=code.slice(i,j5);
        if(kw.has(w)) out+='<span class="tk-kw">'+esc(w)+'</span>';
        else if(code[j5]==="(") out+='<span class="tk-fn">'+esc(w)+'</span>';
        else out+=esc(w);
        i=j5;continue;}
      // pipe / operators
      if("|=<>!+-*/%".indexOf(c)>=0){out+='<span class="tk-op">'+esc(c)+'</span>';i++;continue;}
      out+=esc(c);i++;
    }
    return out;
  }

  function initCode(){
    document.querySelectorAll(".codewrap").forEach(function(w){
      if(w.__done)return; w.__done=true;
      var codeEl=w.querySelector("code");
      var lang=(codeEl.getAttribute("data-lang")||"").toLowerCase();
      var raw=codeEl.textContent;
      w.__raw=raw;
      if(lang==="kql"||lang==="yara"){ codeEl.innerHTML=highlight(raw,lang); }
      var btn=w.querySelector(".copy-btn");
      if(btn){
        btn.addEventListener("click",function(){
          var text=w.__raw;
          navigator.clipboard.writeText(text).then(function(){
            btn.classList.add("done");
            var lbl=btn.querySelector(".lbl"); var prev=lbl?lbl.textContent:"";
            if(lbl)lbl.textContent="Copied";
            setTimeout(function(){btn.classList.remove("done");if(lbl)lbl.textContent=prev||"Copy";},1400);
          }).catch(function(){
            var t=document.createElement("textarea");t.value=text;document.body.appendChild(t);t.select();
            try{document.execCommand("copy");}catch(e){}
            document.body.removeChild(t);btn.classList.add("done");setTimeout(function(){btn.classList.remove("done");},1400);
          });
        });
      }
    });
  }

  function initSidebar(){
    // collapsible sections
    document.querySelectorAll(".nav-sec>.nav-top").forEach(function(b){
      b.addEventListener("click",function(){b.parentElement.classList.toggle("open");});
    });
    // open the section containing the active link + keep it visible
    var act=document.querySelector(".nav-list a.active");
    if(act){var sec=act.closest(".nav-sec");if(sec){sec.classList.add("open");act.scrollIntoView({block:"center"});}}
    // mobile toggle
    var h=document.querySelector(".hamb");
    if(h)h.addEventListener("click",function(){document.body.classList.toggle("nav-open");});
    var sc=document.querySelector(".scrim");
    if(sc)sc.addEventListener("click",function(){document.body.classList.remove("nav-open");});
  }

  window.malchainInitCode=initCode;
  document.addEventListener("DOMContentLoaded",function(){initCode();initSidebar();});
})();

/* ---------- interactive linkage map ---------- */
(function(){
  var NS="http://www.w3.org/2000/svg";
  function el(t,a){var e=document.createElementNS(NS,t);for(var k in a)e.setAttribute(k,a[k]);return e;}
  function esc(s){return s.replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");}
  function initMap(){
    var host=document.getElementById("lkMap"); if(!host)return;
    var g; try{g=JSON.parse(host.getAttribute("data-graph"));}catch(e){return;}
    var nodes=g.nodes, edges=g.edges, phases=g.phases;
    var NW=196,NH=42,VGAP=13,TOP=68,LPAD=20,COLGAP=46,COLSTEP=NW+COLGAP;
    var perCol=[]; nodes.forEach(function(n){perCol[n.p]=Math.max(perCol[n.p]||0,n.r+1);});
    var maxRows=Math.max.apply(null,perCol);
    var W=LPAD*2+phases.length*NW+(phases.length-1)*COLGAP;
    var H=TOP+maxRows*(NH+VGAP)+18;
    nodes.forEach(function(n){n.x=LPAD+n.p*COLSTEP;n.y=TOP+n.r*(NH+VGAP);});
    var svg=el("svg",{viewBox:"0 0 "+W+" "+H,width:W,height:H,role:"img","aria-label":"MalChain technique linkage map"});
    var defs=el("defs",{});
    var mk=el("marker",{id:"lkarrow",markerWidth:"7",markerHeight:"7",refX:"6",refY:"3",orient:"auto"});
    mk.appendChild(el("path",{d:"M0 0 L6 3 L0 6 z",fill:"#DD0F13"})); defs.appendChild(mk); svg.appendChild(defs);
    // phase bands + headers
    phases.forEach(function(pn,i){
      var x=LPAD+i*COLSTEP;
      if(i%2===1) svg.appendChild(el("rect",{x:x-8,y:52,width:NW+16,height:H-58,rx:10,fill:"#000","fill-opacity":"0.022"}));
      var t1=el("text",{x:x,y:32,"class":"lk-col-h"}); t1.textContent=pn; svg.appendChild(t1);
      var cnt=nodes.filter(function(n){return n.p===i;}).length;
      var t2=el("text",{x:x,y:46,"class":"lk-col-sub"}); t2.textContent=cnt+" techniques"; svg.appendChild(t2);
    });
    // edges
    var gE=el("g",{}); svg.appendChild(gE);
    var edgeEls=[], outAdj={}, inAdj={};
    edges.forEach(function(e,ix){
      var s=nodes[e[0]], d=nodes[e[1]];
      var sx=s.x+NW, sy=s.y+NH/2, dx=d.x, dy=d.y+NH/2;
      var h=Math.max(42,Math.abs(dx-sx)*0.42);
      var pth=el("path",{"class":"lk-edge",d:"M"+sx+" "+sy+" C"+(sx+h)+" "+sy+" "+(dx-h)+" "+dy+" "+dx+" "+dy});
      gE.appendChild(pth); edgeEls.push({el:pth,s:e[0],d:e[1]});
      (outAdj[e[0]]=outAdj[e[0]]||[]).push(ix);(inAdj[e[1]]=inAdj[e[1]]||[]).push(ix);
    });
    // nodes
    var nodeEls=[];
    nodes.forEach(function(n,i){
      var gg=el("g",{"class":"lk-node","data-i":i,tabindex:"0"});
      gg.appendChild(el("rect",{x:n.x,y:n.y,width:NW,height:NH,rx:9}));
      var idt=el("text",{x:n.x+13,y:n.y+18,"class":"nid"}); idt.textContent=n.short; gg.appendChild(idt);
      var tt=el("text",{x:n.x+13,y:n.y+33,"class":"ntt"});
      tt.textContent=n.label.length>30?n.label.slice(0,29)+"…":n.label; gg.appendChild(tt);
      var ti=el("title",{}); ti.textContent=n.short+" — "+n.label; gg.appendChild(ti);
      svg.appendChild(gg); nodeEls.push(gg);
    });
    host.appendChild(svg);
    // hard-fit each title to the node width so text never overflows
    nodeEls.forEach(function(gg,i){
      var tt=gg.querySelector(".ntt"); if(!tt||!tt.getComputedTextLength)return;
      var full=nodes[i].label, maxw=NW-26; tt.textContent=full;
      if(tt.getComputedTextLength()>maxw){
        var lo=1,hi=full.length;
        while(lo<hi){var mid=(lo+hi+1)>>1;tt.textContent=full.slice(0,mid)+"\u2026";if(tt.getComputedTextLength()<=maxw)lo=mid;else hi=mid-1;}
        tt.textContent=full.slice(0,lo)+"\u2026";
      }
    });
    var panel=document.getElementById("lkPanel");

    function chips(narr){
      var parts=narr.split(" → ");
      return '<div class="lk-path">'+parts.map(function(p,i){
        var isPhase=/^[A-Z][A-Z /]+$/.test(p.trim());
        return (i?'<span class="lk-sep">→</span>':'')+'<span class="lk-step'+(isPhase?' ph':'')+'">'+esc(p)+'</span>';
      }).join("")+'</div>';
    }
    function enables(n){
      var out="";
      if(n.links.length){
        out+='<div class="lk-en-h">Enables next</div><div class="lk-en">';
        out+=n.links.map(function(l){
          var url="p/"+l.c.toLowerCase()+"/"+l.t.toLowerCase()+".html";
          return '<a class="lk-en-i" href="'+url+'"><span class="rtid">'+l.c+"-"+l.t.split("-")[2]+'</span>'+esc(l.n)+'</a>';
        }).join("");
        out+='</div>';
      }
      if(n.unres && n.unres.length){
        out+='<div class="lk-en">'+n.unres.map(function(u){return '<span class="lk-en-i muted">'+esc(u)+'</span>';}).join("")+'</div>';
      }
      return out;
    }
    function showPanel(n){
      panel.classList.remove("empty");
      panel.innerHTML='<div class="lk-p-head"><span class="pill red">'+n.short+'</span><b>'+esc(n.label)+'</b>'
        +'<a class="lk-p-open" href="p/'+n.code.toLowerCase()+'/'+n.id.toLowerCase()+'.html">Open technique →</a></div>'
        +'<div class="lk-p-sub">Linkage path</div>'+chips(n.narr)+enables(n);
    }
    function hint(){ panel.classList.add("empty"); panel.innerHTML='<span class="lk-hint2">Select a technique above to see its linkage path and the techniques it enables.</span>'; }

    var pinned=null;
    function clear(){svg.classList.remove("focus");nodeEls.forEach(function(e){e.classList.remove("on","src");});edgeEls.forEach(function(o){o.el.classList.remove("on","in");o.el.removeAttribute("marker-end");});}
    function focus(i){
      clear(); svg.classList.add("focus"); nodeEls[i].classList.add("src");
      (outAdj[i]||[]).forEach(function(ix){var o=edgeEls[ix];o.el.classList.add("on");o.el.setAttribute("marker-end","url(#lkarrow)");nodeEls[o.d].classList.add("on");});
      (inAdj[i]||[]).forEach(function(ix){var o=edgeEls[ix];o.el.classList.add("in");nodeEls[o.s].classList.add("on");});
      showPanel(nodes[i]);
    }
    nodeEls.forEach(function(gg,i){
      gg.addEventListener("mouseenter",function(){if(pinned===null)focus(i);});
      gg.addEventListener("focus",function(){if(pinned===null)focus(i);});
      gg.addEventListener("click",function(ev){ev.stopPropagation();if(pinned===i){pinned=null;clear();hint();}else{pinned=i;focus(i);}});
    });
    svg.addEventListener("mouseleave",function(){ if(pinned!==null) focus(pinned); else { clear(); hint(); } });
    svg.addEventListener("click",function(){ pinned=null; clear(); hint(); });
    var rb=document.getElementById("lkReset");
    if(rb)rb.addEventListener("click",function(){ pinned=null; clear(); hint(); });
    // default: preview first node (not pinned) so the panel is populated
    focus(0); pinned=null;
  }
  document.addEventListener("DOMContentLoaded",initMap);
})();
/* ---------- detection library: choose a phase ---------- */
(function(){
  function initDet(){
    var wrap=document.getElementById("detRules"); if(!wrap)return;
    wrap.classList.add("js");
    var tabs=[].slice.call(document.querySelectorAll(".det-tab"));
    var secs=[].slice.call(wrap.querySelectorAll(".det-phase"));
    function show(phase){
      secs.forEach(function(s){s.classList.toggle("active",s.getAttribute("data-phase")===phase);});
      tabs.forEach(function(t){t.classList.toggle("active",t.getAttribute("data-phase")===phase);});
    }
    tabs.forEach(function(t){t.addEventListener("click",function(){show(t.getAttribute("data-phase"));});});
    [].slice.call(document.querySelectorAll("[data-goto]")).forEach(function(a){
      a.addEventListener("click",function(ev){
        ev.preventDefault();
        show(a.getAttribute("data-phase"));
        var el=document.getElementById(a.getAttribute("data-goto"));
        if(el){el.scrollIntoView({behavior:"smooth",block:"start"});el.classList.add("flash");setTimeout(function(){el.classList.remove("flash");},1300);}
      });
    });
  }
  document.addEventListener("DOMContentLoaded",initDet);
})();

/* ---------- live MalwareBazaar samples on technique/mapping pages ---------- */
(function(){
  function esc(s){return String(s==null?"":s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;");}
  function resolveUrl(u){ if(!u)return ""; if(/^(https?:|\/)/.test(u))return u; return (window.SITE_ROOT||"")+u; }
  function fetchSeed(base, seed, cb){
    var u=base+(base.indexOf("?")>=0?"&":"?")+"type="+encodeURIComponent(seed.type)+"&value="+encodeURIComponent(seed.value)+"&limit=6";
    fetch(u,{headers:{"Accept":"application/json"}})
      .then(function(r){return r.json();})
      .then(function(j){ cb((j&&j.query_status==="ok"&&j.data)?j.data:null); })
      .catch(function(){ cb(null); });
  }
  function paint(el, data){
    var seen={}, rows=[];
    data.forEach(function(s){ var h=s.sha256_hash; if(h&&!seen[h]){seen[h]=1; rows.push(s);} });
    rows=rows.slice(0,6);
    if(!rows.length){ el.style.display="none"; return; }
    el.innerHTML='<span class="mwb-live-h">Recent samples</span>'+rows.map(function(s){
      var t=(s.signature||s.file_type||"");
      return '<a class="mwb-s" href="https://bazaar.abuse.ch/sample/'+esc(s.sha256_hash)+'/" target="_blank" rel="noopener" title="'+esc(t)+'"><code>'+esc(s.sha256_hash.slice(0,10))+'…</code>'+(t?' <span>'+esc(t)+'</span>':'')+'</a>';
    }).join("");
  }
  function initMwbLive(){
    var els=document.querySelectorAll(".mwb-live");
    if(!els.length) return;
    var base=resolveUrl(((window.IOC_CONFIG||{}).lookupUrl||"").trim());
    if(!base){ els.forEach(function(e){e.style.display="none";}); return; }
    els.forEach(function(e){
      var seeds; try{seeds=JSON.parse(e.getAttribute("data-seeds"));}catch(x){e.style.display="none";return;}
      if(!seeds||!seeds.length){ e.style.display="none"; return; }
      e.innerHTML='<span class="mwb-live-h mwb-loading">Loading recent samples…</span>';
      var i=0;
      (function next(){
        if(i>=seeds.length){ e.style.display="none"; return; }
        fetchSeed(base, seeds[i++], function(d){ if(d&&d.length) paint(e,d); else next(); });
      })();
    });
  }
  document.addEventListener("DOMContentLoaded", initMwbLive);
})();
