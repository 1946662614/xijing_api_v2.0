(self.webpackChunkant_design_pro=self.webpackChunkant_design_pro||[]).push([[59],{27363:function(we,k){"use strict";var a={icon:{tag:"svg",attrs:{viewBox:"64 64 896 896",focusable:"false"},children:[{tag:"path",attrs:{d:"M257.7 752c2 0 4-.2 6-.5L431.9 722c2-.4 3.9-1.3 5.3-2.8l423.9-423.9a9.96 9.96 0 000-14.1L694.9 114.9c-1.9-1.9-4.4-2.9-7.1-2.9s-5.2 1-7.1 2.9L256.8 538.8c-1.5 1.5-2.4 3.3-2.8 5.3l-29.5 168.2a33.5 33.5 0 009.4 29.8c6.6 6.4 14.9 9.9 23.8 9.9zm67.4-174.4L687.8 215l73.3 73.3-362.7 362.6-88.9 15.7 15.6-89zM880 836H144c-17.7 0-32 14.3-32 32v36c0 4.4 3.6 8 8 8h784c4.4 0 8-3.6 8-8v-36c0-17.7-14.3-32-32-32z"}}]},name:"edit",theme:"outlined"};k.Z=a},86743:function(we,k,a){"use strict";var o=a(30470),F=a(67294),i=a(71577),Ce=a(85432);function Y(E){return!!(E&&E.then)}const R=E=>{const{type:q,children:he,prefixCls:le,buttonProps:re,close:$,autoFocus:I,emitEvent:Ee,quitOnNullishReturnValue:Ie,actionFn:D}=E,H=F.useRef(!1),Ne=F.useRef(null),[ze,Re]=(0,o.Z)(!1),xe=function(){$==null||$.apply(void 0,arguments)};F.useEffect(()=>{let se=null;return I&&(se=setTimeout(()=>{var X;(X=Ne.current)===null||X===void 0||X.focus()})),()=>{se&&clearTimeout(se)}},[]);const Le=se=>{Y(se)&&(Re(!0),se.then(function(){Re(!1,!0),xe.apply(void 0,arguments),H.current=!1},X=>(Re(!1,!0),H.current=!1,Promise.reject(X))))},He=se=>{if(H.current)return;if(H.current=!0,!D){xe();return}let X;if(Ee){if(X=D(se),Ie&&!Y(X)){H.current=!1,xe(se);return}}else if(D.length)X=D($),H.current=!1;else if(X=D(),!X){xe();return}Le(X)};return F.createElement(i.ZP,Object.assign({},(0,Ce.n)(q),{onClick:He,loading:ze,prefixCls:le},re,{ref:Ne}),he)};k.Z=R},69760:function(we,k,a){"use strict";a.d(k,{Z:function(){return Ce}});var o=a(62208),F=a(67294);function i(Y,R,E){return typeof Y=="boolean"?Y:R===void 0?!!E:R!==!1&&R!==null}function Ce(Y,R,E){let q=arguments.length>3&&arguments[3]!==void 0?arguments[3]:F.createElement(o.Z,null),he=arguments.length>4&&arguments[4]!==void 0?arguments[4]:!1;if(!i(Y,R,he))return[!1,null];const re=typeof R=="boolean"||R===void 0||R===null?q:R;return[!0,E?E(re):re]}},36147:function(we,k,a){"use strict";a.d(k,{Z:function(){return Pt}});var o=a(74902),F=a(38135),i=a(67294),Ce=a(17093),Y=a(76278),R=a(17012),E=a(26702),q=a(1558),he=a(94184),le=a.n(he),re=a(86743),$=a(33603),I=a(10110),Ee=a(62208),Ie=a(13328),D=a(69760),H=a(31808),Ne=a(53124),ze=a(65223),Re=a(4173),xe=a(71577),Le=a(85432),He=a(83008);function se(n,u){return i.createElement("span",{className:`${n}-close-x`},u||i.createElement(Ee.Z,{className:`${n}-close-icon`}))}const X=n=>{const{okText:u,okType:m="primary",cancelText:c,confirmLoading:f,onOk:b,onCancel:Z,okButtonProps:x,cancelButtonProps:C}=n,[g]=(0,I.Z)("Modal",(0,He.A)());return i.createElement(i.Fragment,null,i.createElement(xe.ZP,Object.assign({onClick:Z},C),c||(g==null?void 0:g.cancelText)),i.createElement(xe.ZP,Object.assign({},(0,Le.n)(m),{loading:f,onClick:b},x),u||(g==null?void 0:g.okText)))};var Ge=a(71194),_e=function(n,u){var m={};for(var c in n)Object.prototype.hasOwnProperty.call(n,c)&&u.indexOf(c)<0&&(m[c]=n[c]);if(n!=null&&typeof Object.getOwnPropertySymbols=="function")for(var f=0,c=Object.getOwnPropertySymbols(n);f<c.length;f++)u.indexOf(c[f])<0&&Object.prototype.propertyIsEnumerable.call(n,c[f])&&(m[c[f]]=n[c[f]]);return m};let Je;const Ye=n=>{Je={x:n.pageX,y:n.pageY},setTimeout(()=>{Je=null},100)};(0,H.jD)()&&document.documentElement.addEventListener("click",Ye,!0);var et=n=>{var u;const{getPopupContainer:m,getPrefixCls:c,direction:f,modal:b}=i.useContext(Ne.E_),Z=r=>{const{onCancel:t}=n;t==null||t(r)},x=r=>{const{onOk:t}=n;t==null||t(r)},{prefixCls:C,className:g,rootClassName:v,open:w,wrapClassName:O,centered:P,getContainer:T,closeIcon:_,closable:z,focusTriggerAfterClose:M=!0,style:G,visible:ie,width:B=520,footer:W}=n,Se=_e(n,["prefixCls","className","rootClassName","open","wrapClassName","centered","getContainer","closeIcon","closable","focusTriggerAfterClose","style","visible","width","footer"]),Pe=c("modal",C),Ke=c(),[ft,Ue]=(0,Ge.Z)(Pe),Be=le()(O,{[`${Pe}-centered`]:!!P,[`${Pe}-wrap-rtl`]:f==="rtl"}),Tt=W===void 0?i.createElement(X,Object.assign({},n,{onOk:x,onCancel:Z})):W,[e,l]=(0,D.Z)(z,_,r=>se(Pe,r),i.createElement(Ee.Z,{className:`${Pe}-close-icon`}),!0);return ft(i.createElement(Re.BR,null,i.createElement(ze.Ux,{status:!0,override:!0},i.createElement(Ie.Z,Object.assign({width:B},Se,{getContainer:T===void 0?m:T,prefixCls:Pe,rootClassName:le()(Ue,v),wrapClassName:Be,footer:Tt,visible:w!=null?w:ie,mousePosition:(u=Se.mousePosition)!==null&&u!==void 0?u:Je,onClose:Z,closable:e,closeIcon:l,focusTriggerAfterClose:M,transitionName:(0,$.mL)(Ke,"zoom",n.transitionName),maskTransitionName:(0,$.mL)(Ke,"fade",n.maskTransitionName),className:le()(Ue,g,b==null?void 0:b.className),style:Object.assign(Object.assign({},b==null?void 0:b.style),G)})))))};function tt(n){const{icon:u,onCancel:m,onOk:c,close:f,okText:b,okButtonProps:Z,cancelText:x,cancelButtonProps:C,confirmPrefixCls:g,rootPrefixCls:v,type:w,okCancel:O,footer:P,locale:T}=n;let _=u;if(!u&&u!==null)switch(w){case"info":_=i.createElement(q.Z,null);break;case"success":_=i.createElement(Y.Z,null);break;case"error":_=i.createElement(R.Z,null);break;default:_=i.createElement(E.Z,null)}const z=n.okType||"primary",M=O!=null?O:w==="confirm",G=n.autoFocusButton===null?!1:n.autoFocusButton||"ok",[ie]=(0,I.Z)("Modal"),B=T||ie,W=M&&i.createElement(re.Z,{actionFn:m,close:f,autoFocus:G==="cancel",buttonProps:C,prefixCls:`${v}-btn`},x||(B==null?void 0:B.cancelText));return i.createElement("div",{className:`${g}-body-wrapper`},i.createElement("div",{className:`${g}-body`},_,n.title===void 0?null:i.createElement("span",{className:`${g}-title`},n.title),i.createElement("div",{className:`${g}-content`},n.content)),P===void 0?i.createElement("div",{className:`${g}-btns`},W,i.createElement(re.Z,{type:z,actionFn:c,close:f,autoFocus:G==="ok",buttonProps:Z,prefixCls:`${v}-btn`},b||(M?B==null?void 0:B.okText:B==null?void 0:B.justOkText))):P)}var nt=n=>{const{close:u,zIndex:m,afterClose:c,visible:f,open:b,keyboard:Z,centered:x,getContainer:C,maskStyle:g,direction:v,prefixCls:w,wrapClassName:O,rootPrefixCls:P,iconPrefixCls:T,theme:_,bodyStyle:z,closable:M=!1,closeIcon:G,modalRender:ie,focusTriggerAfterClose:B}=n,W=`${w}-confirm`,Se=n.width||416,Pe=n.style||{},Ke=n.mask===void 0?!0:n.mask,ft=n.maskClosable===void 0?!1:n.maskClosable,Ue=le()(W,`${W}-${n.type}`,{[`${W}-rtl`]:v==="rtl"},n.className);return i.createElement(Ce.ZP,{prefixCls:P,iconPrefixCls:T,direction:v,theme:_},i.createElement(et,{prefixCls:w,className:Ue,wrapClassName:le()({[`${W}-centered`]:!!n.centered},O),onCancel:()=>u==null?void 0:u({triggerCancel:!0}),open:b,title:"",footer:null,transitionName:(0,$.mL)(P,"zoom",n.transitionName),maskTransitionName:(0,$.mL)(P,"fade",n.maskTransitionName),mask:Ke,maskClosable:ft,maskStyle:g,style:Pe,bodyStyle:z,width:Se,zIndex:m,afterClose:c,keyboard:Z,centered:x,getContainer:C,closable:M,closeIcon:G,modalRender:ie,focusTriggerAfterClose:B},i.createElement(tt,Object.assign({},n,{confirmPrefixCls:W}))))},Oe=[],yt=function(n,u){var m={};for(var c in n)Object.prototype.hasOwnProperty.call(n,c)&&u.indexOf(c)<0&&(m[c]=n[c]);if(n!=null&&typeof Object.getOwnPropertySymbols=="function")for(var f=0,c=Object.getOwnPropertySymbols(n);f<c.length;f++)u.indexOf(c[f])<0&&Object.prototype.propertyIsEnumerable.call(n,c[f])&&(m[c[f]]=n[c[f]]);return m};let ot="";function bt(){return ot}function Me(n){const u=document.createDocumentFragment();let m=Object.assign(Object.assign({},n),{close:Z,open:!0}),c;function f(){for(var C=arguments.length,g=new Array(C),v=0;v<C;v++)g[v]=arguments[v];const w=g.some(O=>O&&O.triggerCancel);n.onCancel&&w&&n.onCancel.apply(n,[()=>{}].concat((0,o.Z)(g.slice(1))));for(let O=0;O<Oe.length;O++)if(Oe[O]===Z){Oe.splice(O,1);break}(0,F.v)(u)}function b(C){var{okText:g,cancelText:v,prefixCls:w,getContainer:O}=C,P=yt(C,["okText","cancelText","prefixCls","getContainer"]);clearTimeout(c),c=setTimeout(()=>{const T=(0,He.A)(),{getPrefixCls:_,getIconPrefixCls:z,getTheme:M}=(0,Ce.w6)(),G=_(void 0,bt()),ie=w||`${G}-modal`,B=z(),W=M();let Se=O;Se===!1&&(Se=void 0),(0,F.s)(i.createElement(nt,Object.assign({},P,{getContainer:Se,prefixCls:ie,rootPrefixCls:G,iconPrefixCls:B,okText:g,locale:T,theme:W,cancelText:v||T.cancelText})),u)})}function Z(){for(var C=arguments.length,g=new Array(C),v=0;v<C;v++)g[v]=arguments[v];m=Object.assign(Object.assign({},m),{open:!1,afterClose:()=>{typeof n.afterClose=="function"&&n.afterClose(),f.apply(this,g)}}),m.visible&&delete m.visible,b(m)}function x(C){typeof C=="function"?m=C(m):m=Object.assign(Object.assign({},m),C),b(m)}return b(m),Oe.push(Z),{destroy:Z,update:x}}function lt(n){return Object.assign(Object.assign({},n),{type:"warning"})}function rt(n){return Object.assign(Object.assign({},n),{type:"info"})}function st(n){return Object.assign(Object.assign({},n),{type:"success"})}function at(n){return Object.assign(Object.assign({},n),{type:"error"})}function it(n){return Object.assign(Object.assign({},n),{type:"confirm"})}function Ct(n){let{rootPrefixCls:u}=n;ot=u}var ht=function(n,u){var m={};for(var c in n)Object.prototype.hasOwnProperty.call(n,c)&&u.indexOf(c)<0&&(m[c]=n[c]);if(n!=null&&typeof Object.getOwnPropertySymbols=="function")for(var f=0,c=Object.getOwnPropertySymbols(n);f<c.length;f++)u.indexOf(c[f])<0&&Object.prototype.propertyIsEnumerable.call(n,c[f])&&(m[c[f]]=n[c[f]]);return m},Lt=n=>{const{prefixCls:u,className:m,closeIcon:c,closable:f,type:b,title:Z,children:x}=n,C=ht(n,["prefixCls","className","closeIcon","closable","type","title","children"]),{getPrefixCls:g}=i.useContext(Ne.E_),v=g(),w=u||g("modal"),[,O]=(0,Ge.Z)(w),P=`${w}-confirm`;let T={};return b?T={closable:f!=null?f:!1,title:"",footer:"",children:i.createElement(tt,Object.assign({},n,{confirmPrefixCls:P,rootPrefixCls:v,content:x}))}:T={closable:f!=null?f:!0,title:Z,footer:n.footer===void 0?i.createElement(X,Object.assign({},n)):n.footer,children:x},i.createElement(Ie.s,Object.assign({prefixCls:w,className:le()(O,`${w}-pure-panel`,b&&P,b&&`${P}-${b}`,m)},C,{closeIcon:se(w,c),closable:f},T))};function xt(){const[n,u]=i.useState([]),m=i.useCallback(c=>(u(f=>[].concat((0,o.Z)(f),[c])),()=>{u(f=>f.filter(b=>b!==c))}),[]);return[n,m]}var Ot=a(24457);const $t=(n,u)=>{let{afterClose:m,config:c}=n;var f;const[b,Z]=i.useState(!0),[x,C]=i.useState(c),{direction:g,getPrefixCls:v}=i.useContext(Ne.E_),w=v("modal"),O=v(),P=()=>{var M;m(),(M=x.afterClose)===null||M===void 0||M.call(x)},T=function(){Z(!1);for(var M=arguments.length,G=new Array(M),ie=0;ie<M;ie++)G[ie]=arguments[ie];const B=G.some(W=>W&&W.triggerCancel);x.onCancel&&B&&x.onCancel.apply(x,[()=>{}].concat((0,o.Z)(G.slice(1))))};i.useImperativeHandle(u,()=>({destroy:T,update:M=>{C(G=>Object.assign(Object.assign({},G),M))}}));const _=(f=x.okCancel)!==null&&f!==void 0?f:x.type==="confirm",[z]=(0,I.Z)("Modal",Ot.Z.Modal);return i.createElement(nt,Object.assign({prefixCls:w,rootPrefixCls:O},x,{close:T,open:b,afterClose:P,okText:x.okText||(_?z==null?void 0:z.okText:z==null?void 0:z.justOkText),direction:x.direction||g,cancelText:x.cancelText||(z==null?void 0:z.cancelText)}))};var ct=i.forwardRef($t);let We=0;const Zt=i.memo(i.forwardRef((n,u)=>{const[m,c]=xt();return i.useImperativeHandle(u,()=>({patchElement:c}),[]),i.createElement(i.Fragment,null,m)}));function St(){const n=i.useRef(null),[u,m]=i.useState([]);i.useEffect(()=>{u.length&&((0,o.Z)(u).forEach(Z=>{Z()}),m([]))},[u]);const c=i.useCallback(b=>function(x){var C;We+=1;const g=i.createRef();let v;const w=i.createElement(ct,{key:`modal-${We}`,config:b(x),ref:g,afterClose:()=>{v==null||v()}});return v=(C=n.current)===null||C===void 0?void 0:C.patchElement(w),v&&Oe.push(v),{destroy:()=>{function O(){var P;(P=g.current)===null||P===void 0||P.destroy()}g.current?O():m(P=>[].concat((0,o.Z)(P),[O]))},update:O=>{function P(){var T;(T=g.current)===null||T===void 0||T.update(O)}g.current?P():m(T=>[].concat((0,o.Z)(T),[P]))}}},[]);return[i.useMemo(()=>({info:c(rt),success:c(st),error:c(at),warning:c(lt),confirm:c(it)}),[]),i.createElement(Zt,{key:"modal-holder",ref:n})]}var dt=St;function ut(n){return Me(lt(n))}const ae=et;ae.useModal=dt,ae.info=function(u){return Me(rt(u))},ae.success=function(u){return Me(st(u))},ae.error=function(u){return Me(at(u))},ae.warning=ut,ae.warn=ut,ae.confirm=function(u){return Me(it(u))},ae.destroyAll=function(){for(;Oe.length;){const u=Oe.pop();u&&u()}},ae.config=Ct,ae._InternalPanelDoNotUseOrYouWillBeFired=Lt;var Pt=ae},25514:function(we,k,a){"use strict";a.d(k,{Z:function(){return Tt}});var o=a(67294),F=a(64894),i=a(87462),Ce=a(48820),Y=a(93771),R=function(l,r){return o.createElement(Y.Z,(0,i.Z)({},l,{ref:r,icon:Ce.Z}))},E=o.forwardRef(R),q=a(27363),he=function(l,r){return o.createElement(Y.Z,(0,i.Z)({},l,{ref:r,icon:q.Z}))},le=o.forwardRef(he),re=a(94184),$=a.n(re),I=a(20640),Ee=a.n(I),Ie=a(9220),D=a(50344),H=a(8410),Ne=a(21770),ze=a(98423),Re=a(42550),xe=a(79370),Le=a(15105),He=function(e,l){var r={};for(var t in e)Object.prototype.hasOwnProperty.call(e,t)&&l.indexOf(t)<0&&(r[t]=e[t]);if(e!=null&&typeof Object.getOwnPropertySymbols=="function")for(var s=0,t=Object.getOwnPropertySymbols(e);s<t.length;s++)l.indexOf(t[s])<0&&Object.prototype.propertyIsEnumerable.call(e,t[s])&&(r[t[s]]=e[t[s]]);return r};const se={border:0,background:"transparent",padding:0,lineHeight:"inherit",display:"inline-block"};var Ge=o.forwardRef((e,l)=>{const r=L=>{const{keyCode:h}=L;h===Le.Z.ENTER&&L.preventDefault()},t=L=>{const{keyCode:h}=L,{onClick:te}=e;h===Le.Z.ENTER&&te&&te()},{style:s,noStyle:N,disabled:K}=e,ee=He(e,["style","noStyle","disabled"]);let j={};return N||(j=Object.assign({},se)),K&&(j.pointerEvents="none"),j=Object.assign(Object.assign({},j),s),o.createElement("div",Object.assign({role:"button",tabIndex:0,ref:l},ee,{onKeyDown:r,onKeyUp:t,style:j}))}),_e=a(53124),Je=a(10110),Ye=a(83062),It={icon:{tag:"svg",attrs:{viewBox:"64 64 896 896",focusable:"false"},children:[{tag:"path",attrs:{d:"M864 170h-60c-4.4 0-8 3.6-8 8v518H310v-73c0-6.7-7.8-10.5-13-6.3l-141.9 112a8 8 0 000 12.6l141.9 112c5.3 4.2 13 .4 13-6.3v-75h498c35.3 0 64-28.7 64-64V178c0-4.4-3.6-8-8-8z"}}]},name:"enter",theme:"outlined"},et=It,tt=function(l,r){return o.createElement(Y.Z,(0,i.Z)({},l,{ref:r,icon:et}))},Nt=o.forwardRef(tt),nt=a(96159),Rt=a(22913),Oe=a(49867),yt=a(67968),ot=a(78589),bt=a(47673);const Me=(e,l,r,t)=>{const{titleMarginBottom:s,fontWeightStrong:N}=t;return{marginBottom:s,color:r,fontWeight:N,fontSize:e,lineHeight:l}},lt=e=>{const l=[1,2,3,4,5],r={};return l.forEach(t=>{r[`
      h${t}&,
      div&-h${t},
      div&-h${t} > textarea,
      h${t}
    `]=Me(e[`fontSizeHeading${t}`],e[`lineHeightHeading${t}`],e.colorTextHeading,e)}),r},rt=e=>{const{componentCls:l}=e;return{"a&, a":Object.assign(Object.assign({},(0,Oe.N)(e)),{textDecoration:e.linkDecoration,"&:active, &:hover":{textDecoration:e.linkHoverDecoration},[`&[disabled], &${l}-disabled`]:{color:e.colorTextDisabled,cursor:"not-allowed","&:active, &:hover":{color:e.colorTextDisabled},"&:active":{pointerEvents:"none"}}})}},st=e=>({code:{margin:"0 0.2em",paddingInline:"0.4em",paddingBlock:"0.2em 0.1em",fontSize:"85%",fontFamily:e.fontFamilyCode,background:"rgba(150, 150, 150, 0.1)",border:"1px solid rgba(100, 100, 100, 0.2)",borderRadius:3},kbd:{margin:"0 0.2em",paddingInline:"0.4em",paddingBlock:"0.15em 0.1em",fontSize:"90%",fontFamily:e.fontFamilyCode,background:"rgba(150, 150, 150, 0.06)",border:"1px solid rgba(100, 100, 100, 0.2)",borderBottomWidth:2,borderRadius:3},mark:{padding:0,backgroundColor:ot.EV[2]},"u, ins":{textDecoration:"underline",textDecorationSkipInk:"auto"},"s, del":{textDecoration:"line-through"},strong:{fontWeight:600},"ul, ol":{marginInline:0,marginBlock:"0 1em",padding:0,li:{marginInline:"20px 0",marginBlock:0,paddingInline:"4px 0",paddingBlock:0}},ul:{listStyleType:"circle",ul:{listStyleType:"disc"}},ol:{listStyleType:"decimal"},"pre, blockquote":{margin:"1em 0"},pre:{padding:"0.4em 0.6em",whiteSpace:"pre-wrap",wordWrap:"break-word",background:"rgba(150, 150, 150, 0.1)",border:"1px solid rgba(100, 100, 100, 0.2)",borderRadius:3,fontFamily:e.fontFamilyCode,code:{display:"inline",margin:0,padding:0,fontSize:"inherit",fontFamily:"inherit",background:"transparent",border:0}},blockquote:{paddingInline:"0.6em 0",paddingBlock:0,borderInlineStart:"4px solid rgba(100, 100, 100, 0.2)",opacity:.85}}),at=e=>{const{componentCls:l}=e,t=(0,bt.e5)(e).inputPaddingVertical+1;return{"&-edit-content":{position:"relative","div&":{insetInlineStart:-e.paddingSM,marginTop:-t,marginBottom:`calc(1em - ${t}px)`},[`${l}-edit-content-confirm`]:{position:"absolute",insetInlineEnd:e.marginXS+2,insetBlockEnd:e.marginXS,color:e.colorTextDescription,fontWeight:"normal",fontSize:e.fontSize,fontStyle:"normal",pointerEvents:"none"},textarea:{margin:"0!important",MozTransition:"none",height:"1em"}}}},it=e=>({"&-copy-success":{[`
    &,
    &:hover,
    &:focus`]:{color:e.colorSuccess}}}),Ct=()=>({[`
  a&-ellipsis,
  span&-ellipsis
  `]:{display:"inline-block",maxWidth:"100%"},"&-single-line":{whiteSpace:"nowrap"},"&-ellipsis-single-line":{overflow:"hidden",textOverflow:"ellipsis","a&, span&":{verticalAlign:"bottom"}},"&-ellipsis-multiple-line":{display:"-webkit-box",overflow:"hidden",WebkitLineClamp:3,WebkitBoxOrient:"vertical"}}),ht=e=>{const{componentCls:l,titleMarginTop:r}=e;return{[l]:Object.assign(Object.assign(Object.assign(Object.assign(Object.assign(Object.assign(Object.assign(Object.assign(Object.assign({color:e.colorText,wordBreak:"break-word",lineHeight:e.lineHeight,[`&${l}-secondary`]:{color:e.colorTextDescription},[`&${l}-success`]:{color:e.colorSuccess},[`&${l}-warning`]:{color:e.colorWarning},[`&${l}-danger`]:{color:e.colorError,"a&:active, a&:focus":{color:e.colorErrorActive},"a&:hover":{color:e.colorErrorHover}},[`&${l}-disabled`]:{color:e.colorTextDisabled,cursor:"not-allowed",userSelect:"none"},[`
        div&,
        p
      `]:{marginBottom:"1em"}},lt(e)),{[`
      & + h1${l},
      & + h2${l},
      & + h3${l},
      & + h4${l},
      & + h5${l}
      `]:{marginTop:r},[`
      div,
      ul,
      li,
      p,
      h1,
      h2,
      h3,
      h4,
      h5`]:{[`
        + h1,
        + h2,
        + h3,
        + h4,
        + h5
        `]:{marginTop:r}}}),st(e)),rt(e)),{[`
        ${l}-expand,
        ${l}-edit,
        ${l}-copy
      `]:Object.assign(Object.assign({},(0,Oe.N)(e)),{marginInlineStart:e.marginXXS})}),at(e)),it(e)),Ct()),{"&-rtl":{direction:"rtl"}})}};var Et=(0,yt.Z)("Typography",e=>[ht(e)],()=>({titleMarginTop:"1.2em",titleMarginBottom:"0.5em"})),xt=e=>{const{prefixCls:l,"aria-label":r,className:t,style:s,direction:N,maxLength:K,autoSize:ee=!0,value:j,onSave:L,onCancel:h,onEnd:te,component:A,enterIcon:J=o.createElement(Nt,null)}=e,ce=o.useRef(null),de=o.useRef(!1),ge=o.useRef(),[ve,ne]=o.useState(j);o.useEffect(()=>{ne(j)},[j]),o.useEffect(()=>{if(ce.current&&ce.current.resizableTextArea){const{textArea:ue}=ce.current.resizableTextArea;ue.focus();const{length:me}=ue.value;ue.setSelectionRange(me,me)}},[]);const y=ue=>{let{target:me}=ue;ne(me.value.replace(/[\n\r]/g,""))},je=()=>{de.current=!0},Ae=()=>{de.current=!1},U=ue=>{let{keyCode:me}=ue;de.current||(ge.current=me)},Ve=()=>{L(ve.trim())},V=ue=>{let{keyCode:me,ctrlKey:jt,altKey:qe,metaKey:Ze,shiftKey:Qe}=ue;ge.current===me&&!de.current&&!jt&&!qe&&!Ze&&!Qe&&(me===Le.Z.ENTER?(Ve(),te==null||te()):me===Le.Z.ESC&&h())},S=()=>{Ve()},fe=A?`${l}-${A}`:"",[Fe,$e]=Et(l),Te=$()(l,`${l}-edit-content`,{[`${l}-rtl`]:N==="rtl"},t,fe,$e);return Fe(o.createElement("div",{className:Te,style:s},o.createElement(Rt.Z,{ref:ce,maxLength:K,value:ve,onChange:y,onKeyDown:U,onKeyUp:V,onCompositionStart:je,onCompositionEnd:Ae,onBlur:S,"aria-label":r,rows:1,autoSize:ee}),J!==null?(0,nt.Tm)(J,{className:`${l}-edit-content-confirm`}):null))},Ot=function(e,l){var r={};for(var t in e)Object.prototype.hasOwnProperty.call(e,t)&&l.indexOf(t)<0&&(r[t]=e[t]);if(e!=null&&typeof Object.getOwnPropertySymbols=="function")for(var s=0,t=Object.getOwnPropertySymbols(e);s<t.length;s++)l.indexOf(t[s])<0&&Object.prototype.propertyIsEnumerable.call(e,t[s])&&(r[t[s]]=e[t[s]]);return r},ct=o.forwardRef((e,l)=>{const{prefixCls:r,component:t="article",className:s,rootClassName:N,setContentRef:K,children:ee,direction:j,style:L}=e,h=Ot(e,["prefixCls","component","className","rootClassName","setContentRef","children","direction","style"]),{getPrefixCls:te,direction:A,typography:J}=o.useContext(_e.E_),ce=j!=null?j:A;let de=l;K&&(de=(0,Re.sQ)(l,K));const ge=te("typography",r),[ve,ne]=Et(ge),y=$()(ge,J==null?void 0:J.className,{[`${ge}-rtl`]:ce==="rtl"},s,N,ne),je=Object.assign(Object.assign({},J==null?void 0:J.style),L);return ve(o.createElement(t,Object.assign({className:y,style:je,ref:de},h),ee))});function We(e,l){return o.useMemo(()=>{const r=!!e;return[r,Object.assign(Object.assign({},l),r&&typeof e=="object"?e:null)]},[e])}var St=(e,l)=>{const r=o.useRef(!1);o.useEffect(()=>{r.current?e():r.current=!0},l)};function dt(e){const l=typeof e;return l==="string"||l==="number"}function ut(e){let l=0;return e.forEach(r=>{dt(r)?l+=String(r).length:l+=1}),l}function ae(e,l){let r=0;const t=[];for(let s=0;s<e.length;s+=1){if(r===l)return t;const N=e[s],ee=dt(N)?String(N).length:1,j=r+ee;if(j>l){const L=l-r;return t.push(String(N).slice(0,L)),t}t.push(N),r=j}return e}const Pt=0,n=1,u=2,m=3,c=4;var b=e=>{let{enabledMeasure:l,children:r,text:t,width:s,fontSize:N,rows:K,onEllipsis:ee}=e;const[[j,L,h],te]=o.useState([0,0,0]),[A,J]=o.useState(Pt),[ce,de]=o.useState(0),ge=o.useRef(null),ve=o.useRef(null),ne=o.useMemo(()=>(0,D.Z)(t),[t]),y=o.useMemo(()=>ut(ne),[ne]),je=o.useMemo(()=>!l||A!==m?r(ne,!1):r(ae(ne,L),L<y),[l,A,r,ne,L,y]);(0,H.Z)(()=>{l&&s&&N&&y&&(J(n),te([0,Math.ceil(y/2),y]))},[l,s,N,t,y,K]),(0,H.Z)(()=>{var V;A===n&&de(((V=ge.current)===null||V===void 0?void 0:V.offsetHeight)||0)},[A]),(0,H.Z)(()=>{var V,S;if(ce){if(A===n){const fe=((V=ve.current)===null||V===void 0?void 0:V.offsetHeight)||0,Fe=K*ce;fe<=Fe?(J(c),ee(!1)):J(u)}else if(A===u)if(j!==h){const fe=((S=ve.current)===null||S===void 0?void 0:S.offsetHeight)||0,Fe=K*ce;let $e=j,Te=h;j===h-1?Te=j:fe<=Fe?$e=L:Te=L;const ue=Math.ceil(($e+Te)/2);te([$e,ue,Te])}else J(m),ee(!0)}},[A,j,h,K,ce]);const Ae={width:s,whiteSpace:"normal",margin:0,padding:0},U=(V,S,fe)=>o.createElement("span",{"aria-hidden":!0,ref:S,style:Object.assign({position:"fixed",display:"block",left:0,top:0,zIndex:-9999,visibility:"hidden",pointerEvents:"none",fontSize:Math.floor(N/2)*2},fe)},V),Ve=(V,S)=>{const fe=ae(ne,V);return U(r(fe,!0),S,Ae)};return o.createElement(o.Fragment,null,je,l&&A!==m&&A!==c&&o.createElement(o.Fragment,null,U("lg",ge,{wordBreak:"keep-all",whiteSpace:"nowrap"}),A===n?U(r(ne,!1),ve,Ae):Ve(L,ve)))},x=e=>{let{enabledEllipsis:l,isEllipsis:r,children:t,tooltipProps:s}=e;return!(s!=null&&s.title)||!l?t:o.createElement(Ye.Z,Object.assign({open:r?void 0:!1},s),t)},C=function(e,l){var r={};for(var t in e)Object.prototype.hasOwnProperty.call(e,t)&&l.indexOf(t)<0&&(r[t]=e[t]);if(e!=null&&typeof Object.getOwnPropertySymbols=="function")for(var s=0,t=Object.getOwnPropertySymbols(e);s<t.length;s++)l.indexOf(t[s])<0&&Object.prototype.propertyIsEnumerable.call(e,t[s])&&(r[t[s]]=e[t[s]]);return r};function g(e,l){let{mark:r,code:t,underline:s,delete:N,strong:K,keyboard:ee,italic:j}=e,L=l;function h(te,A){A&&(L=o.createElement(te,{},L))}return h("strong",K),h("u",s),h("del",N),h("code",t),h("mark",r),h("kbd",ee),h("i",j),L}function v(e,l,r){return e===!0||e===void 0?l:e||r&&l}function w(e){return e===!1?[!1,!1]:Array.isArray(e)?e:[e]}const O="...";var T=o.forwardRef((e,l)=>{var r,t,s;const{prefixCls:N,className:K,style:ee,type:j,disabled:L,children:h,ellipsis:te,editable:A,copyable:J,component:ce,title:de}=e,ge=C(e,["prefixCls","className","style","type","disabled","children","ellipsis","editable","copyable","component","title"]),{getPrefixCls:ve,direction:ne}=o.useContext(_e.E_),[y]=(0,Je.Z)("Text"),je=o.useRef(null),Ae=o.useRef(null),U=ve("typography",N),Ve=(0,ze.Z)(ge,["mark","code","delete","underline","strong","keyboard","italic"]),[V,S]=We(A),[fe,Fe]=(0,Ne.Z)(!1,{value:S.editing}),{triggerType:$e=["icon"]}=S,Te=d=>{var p;d&&((p=S.onStart)===null||p===void 0||p.call(S)),Fe(d)};St(()=>{var d;fe||(d=Ae.current)===null||d===void 0||d.focus()},[fe]);const ue=d=>{d==null||d.preventDefault(),Te(!0)},me=d=>{var p;(p=S.onChange)===null||p===void 0||p.call(S,d),Te(!1)},jt=()=>{var d;(d=S.onCancel)===null||d===void 0||d.call(S),Te(!1)},[qe,Ze]=We(J),[Qe,Dt]=o.useState(!1),wt=o.useRef(null),kt={};Ze.format&&(kt.format=Ze.format);const Mt=()=>{wt.current&&clearTimeout(wt.current)},Wt=d=>{var p;d==null||d.preventDefault(),d==null||d.stopPropagation(),Ee()(Ze.text||String(h)||"",kt),Dt(!0),Mt(),wt.current=setTimeout(()=>{Dt(!1)},3e3),(p=Ze.onCopy)===null||p===void 0||p.call(Ze,d)};o.useEffect(()=>Mt,[]);const[Bt,Kt]=o.useState(!1),[At,Ut]=o.useState(!1),[Vt,Qt]=o.useState(!1),[Ft,Xt]=o.useState(!1),[zt,Gt]=o.useState(!1),[Jt,Yt]=o.useState(!0),[De,Q]=We(te,{expandable:!1}),ye=De&&!Vt,{rows:Xe=1}=Q,mt=o.useMemo(()=>!ye||Q.suffix!==void 0||Q.onEllipsis||Q.expandable||V||qe,[ye,Q,V,qe]);(0,H.Z)(()=>{De&&!mt&&(Kt((0,xe.G)("webkitLineClamp")),Ut((0,xe.G)("textOverflow")))},[mt,De]);const be=o.useMemo(()=>mt?!1:Xe===1?At:Bt,[mt,At,Bt]),Ht=ye&&(be?zt:Ft),qt=ye&&Xe===1&&be,pt=ye&&Xe>1&&be,_t=d=>{var p;Qt(!0),(p=Q.onExpand)===null||p===void 0||p.call(Q,d)},[en,tn]=o.useState(0),[nn,on]=o.useState(0),ln=(d,p)=>{let{offsetWidth:oe}=d;var pe;tn(oe),on(parseInt((pe=window.getComputedStyle)===null||pe===void 0?void 0:pe.call(window,p).fontSize,10)||0)},rn=d=>{var p;Xt(d),Ft!==d&&((p=Q.onEllipsis)===null||p===void 0||p.call(Q,d))};o.useEffect(()=>{const d=je.current;if(De&&be&&d){const p=pt?d.offsetHeight<d.scrollHeight:d.offsetWidth<d.scrollWidth;zt!==p&&Gt(p)}},[De,be,h,pt,Jt]),o.useEffect(()=>{const d=je.current;if(typeof IntersectionObserver=="undefined"||!d||!be||!ye)return;const p=new IntersectionObserver(()=>{Yt(!!d.offsetParent)});return p.observe(d),()=>{p.disconnect()}},[be,ye]);let ke={};Q.tooltip===!0?ke={title:(r=S.text)!==null&&r!==void 0?r:h}:o.isValidElement(Q.tooltip)?ke={title:Q.tooltip}:typeof Q.tooltip=="object"?ke=Object.assign({title:(t=S.text)!==null&&t!==void 0?t:h},Q.tooltip):ke={title:Q.tooltip};const gt=o.useMemo(()=>{const d=p=>["string","number"].includes(typeof p);if(!(!De||be)){if(d(S.text))return S.text;if(d(h))return h;if(d(de))return de;if(d(ke.title))return ke.title}},[De,be,de,ke.title,Ht]);if(fe)return o.createElement(xt,{value:(s=S.text)!==null&&s!==void 0?s:typeof h=="string"?h:"",onSave:me,onCancel:jt,onEnd:S.onEnd,prefixCls:U,className:K,style:ee,direction:ne,component:ce,maxLength:S.maxLength,autoSize:S.autoSize,enterIcon:S.enterIcon});const sn=()=>{const{expandable:d,symbol:p}=Q;if(!d)return null;let oe;return p?oe=p:oe=y==null?void 0:y.expand,o.createElement("a",{key:"expand",className:`${U}-expand`,onClick:_t,"aria-label":y==null?void 0:y.expand},oe)},an=()=>{if(!V)return;const{icon:d,tooltip:p}=S,oe=(0,D.Z)(p)[0]||(y==null?void 0:y.edit),pe=typeof oe=="string"?oe:"";return $e.includes("icon")?o.createElement(Ye.Z,{key:"edit",title:p===!1?"":oe},o.createElement(Ge,{ref:Ae,className:`${U}-edit`,onClick:ue,"aria-label":pe},d||o.createElement(le,{role:"button"}))):null},cn=()=>{if(!qe)return;const{tooltips:d,icon:p}=Ze,oe=w(d),pe=w(p),vt=Qe?v(oe[1],y==null?void 0:y.copied):v(oe[0],y==null?void 0:y.copy),fn=Qe?y==null?void 0:y.copied:y==null?void 0:y.copy,mn=typeof vt=="string"?vt:fn;return o.createElement(Ye.Z,{key:"copy",title:vt},o.createElement(Ge,{className:$()(`${U}-copy`,Qe&&`${U}-copy-success`),onClick:Wt,"aria-label":mn},Qe?v(pe[1],o.createElement(F.Z,null),!0):v(pe[0],o.createElement(E,null),!0)))},dn=d=>[d&&sn(),an(),cn()],un=d=>[d&&o.createElement("span",{"aria-hidden":!0,key:"ellipsis"},O),Q.suffix,dn(d)];return o.createElement(Ie.Z,{onResize:ln,disabled:!ye||be},d=>o.createElement(x,{tooltipProps:ke,enabledEllipsis:ye,isEllipsis:Ht},o.createElement(ct,Object.assign({className:$()({[`${U}-${j}`]:j,[`${U}-disabled`]:L,[`${U}-ellipsis`]:De,[`${U}-single-line`]:ye&&Xe===1,[`${U}-ellipsis-single-line`]:qt,[`${U}-ellipsis-multiple-line`]:pt},K),prefixCls:N,style:Object.assign(Object.assign({},ee),{WebkitLineClamp:pt?Xe:void 0}),component:ce,ref:(0,Re.sQ)(d,je,l),direction:ne,onClick:$e.includes("text")?ue:void 0,"aria-label":gt==null?void 0:gt.toString(),title:de},Ve),o.createElement(b,{enabledMeasure:ye&&!be,text:h,rows:Xe,width:en,fontSize:nn,onEllipsis:rn},(p,oe)=>{let pe=p;return p.length&&oe&&gt&&(pe=o.createElement("span",{key:"show-content","aria-hidden":!0},pe)),g(e,o.createElement(o.Fragment,null,pe,un(oe)))}))))}),_=function(e,l){var r={};for(var t in e)Object.prototype.hasOwnProperty.call(e,t)&&l.indexOf(t)<0&&(r[t]=e[t]);if(e!=null&&typeof Object.getOwnPropertySymbols=="function")for(var s=0,t=Object.getOwnPropertySymbols(e);s<t.length;s++)l.indexOf(t[s])<0&&Object.prototype.propertyIsEnumerable.call(e,t[s])&&(r[t[s]]=e[t[s]]);return r},M=o.forwardRef((e,l)=>{var{ellipsis:r,rel:t}=e,s=_(e,["ellipsis","rel"]);const N=Object.assign(Object.assign({},s),{rel:t===void 0&&s.target==="_blank"?"noopener noreferrer":t});return delete N.navigate,o.createElement(T,Object.assign({},N,{ref:l,ellipsis:!!r,component:"a"}))}),ie=o.forwardRef((e,l)=>o.createElement(T,Object.assign({ref:l},e,{component:"div"}))),B=function(e,l){var r={};for(var t in e)Object.prototype.hasOwnProperty.call(e,t)&&l.indexOf(t)<0&&(r[t]=e[t]);if(e!=null&&typeof Object.getOwnPropertySymbols=="function")for(var s=0,t=Object.getOwnPropertySymbols(e);s<t.length;s++)l.indexOf(t[s])<0&&Object.prototype.propertyIsEnumerable.call(e,t[s])&&(r[t[s]]=e[t[s]]);return r};const W=(e,l)=>{var{ellipsis:r}=e,t=B(e,["ellipsis"]);const s=o.useMemo(()=>r&&typeof r=="object"?(0,ze.Z)(r,["expandable","rows"]):r,[r]);return o.createElement(T,Object.assign({ref:l},t,{ellipsis:s,component:"span"}))};var Se=o.forwardRef(W),Pe=function(e,l){var r={};for(var t in e)Object.prototype.hasOwnProperty.call(e,t)&&l.indexOf(t)<0&&(r[t]=e[t]);if(e!=null&&typeof Object.getOwnPropertySymbols=="function")for(var s=0,t=Object.getOwnPropertySymbols(e);s<t.length;s++)l.indexOf(t[s])<0&&Object.prototype.propertyIsEnumerable.call(e,t[s])&&(r[t[s]]=e[t[s]]);return r};const Ke=[1,2,3,4,5];var Ue=o.forwardRef((e,l)=>{const{level:r=1}=e,t=Pe(e,["level"]);let s;return Ke.includes(r)?s=`h${r}`:s="h1",o.createElement(T,Object.assign({ref:l},t,{component:s}))});const Be=ct;Be.Text=Se,Be.Link=M,Be.Title=Ue,Be.Paragraph=ie;var Tt=Be},20640:function(we,k,a){"use strict";var o=a(11742),F={"text/plain":"Text","text/html":"Url",default:"Text"},i="Copy to clipboard: #{key}, Enter";function Ce(R){var E=(/mac os x/i.test(navigator.userAgent)?"\u2318":"Ctrl")+"+C";return R.replace(/#{\s*key\s*}/g,E)}function Y(R,E){var q,he,le,re,$,I,Ee=!1;E||(E={}),q=E.debug||!1;try{le=o(),re=document.createRange(),$=document.getSelection(),I=document.createElement("span"),I.textContent=R,I.ariaHidden="true",I.style.all="unset",I.style.position="fixed",I.style.top=0,I.style.clip="rect(0, 0, 0, 0)",I.style.whiteSpace="pre",I.style.webkitUserSelect="text",I.style.MozUserSelect="text",I.style.msUserSelect="text",I.style.userSelect="text",I.addEventListener("copy",function(D){if(D.stopPropagation(),E.format)if(D.preventDefault(),typeof D.clipboardData=="undefined"){q&&console.warn("unable to use e.clipboardData"),q&&console.warn("trying IE specific stuff"),window.clipboardData.clearData();var H=F[E.format]||F.default;window.clipboardData.setData(H,R)}else D.clipboardData.clearData(),D.clipboardData.setData(E.format,R);E.onCopy&&(D.preventDefault(),E.onCopy(D.clipboardData))}),document.body.appendChild(I),re.selectNodeContents(I),$.addRange(re);var Ie=document.execCommand("copy");if(!Ie)throw new Error("copy command was unsuccessful");Ee=!0}catch(D){q&&console.error("unable to copy using execCommand: ",D),q&&console.warn("trying IE specific stuff");try{window.clipboardData.setData(E.format||"text",R),E.onCopy&&E.onCopy(window.clipboardData),Ee=!0}catch(H){q&&console.error("unable to copy using clipboardData: ",H),q&&console.error("falling back to prompt"),he=Ce("message"in E?E.message:i),window.prompt(he,R)}}finally{$&&(typeof $.removeRange=="function"?$.removeRange(re):$.removeAllRanges()),I&&document.body.removeChild(I),le()}return Ee}we.exports=Y},11742:function(we){we.exports=function(){var k=document.getSelection();if(!k.rangeCount)return function(){};for(var a=document.activeElement,o=[],F=0;F<k.rangeCount;F++)o.push(k.getRangeAt(F));switch(a.tagName.toUpperCase()){case"INPUT":case"TEXTAREA":a.blur();break;default:a=null;break}return k.removeAllRanges(),function(){k.type==="Caret"&&k.removeAllRanges(),k.rangeCount||o.forEach(function(i){k.addRange(i)}),a&&a.focus()}}}}]);