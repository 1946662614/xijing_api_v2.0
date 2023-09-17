"use strict";(self.webpackChunkant_design_pro=self.webpackChunkant_design_pro||[]).push([[676],{4393:function($e,K,s){s.d(K,{Z:function(){return n}});var U=s(94184),S=s.n(U),V=s(98423),o=s(67294),T=s(53124),M=s(98675),J=s(99559),Q=s(48055),ce=function(e,r){var t={};for(var a in e)Object.prototype.hasOwnProperty.call(e,a)&&r.indexOf(a)<0&&(t[a]=e[a]);if(e!=null&&typeof Object.getOwnPropertySymbols=="function")for(var i=0,a=Object.getOwnPropertySymbols(e);i<a.length;i++)r.indexOf(a[i])<0&&Object.prototype.propertyIsEnumerable.call(e,a[i])&&(t[a[i]]=e[a[i]]);return t},q=e=>{var{prefixCls:r,className:t,hoverable:a=!0}=e,i=ce(e,["prefixCls","className","hoverable"]);const{getPrefixCls:l}=o.useContext(T.E_),m=l("card",r),p=S()(`${m}-grid`,t,{[`${m}-grid-hoverable`]:a});return o.createElement("div",Object.assign({},i,{className:p}))},v=s(14747),N=s(67968),de=s(45503);const L=e=>{const{antCls:r,componentCls:t,headerHeight:a,cardPaddingBase:i,tabsMarginBottom:l}=e;return Object.assign(Object.assign({display:"flex",justifyContent:"center",flexDirection:"column",minHeight:a,marginBottom:-1,padding:`0 ${i}px`,color:e.colorTextHeading,fontWeight:e.fontWeightStrong,fontSize:e.headerFontSize,background:e.headerBg,borderBottom:`${e.lineWidth}px ${e.lineType} ${e.colorBorderSecondary}`,borderRadius:`${e.borderRadiusLG}px ${e.borderRadiusLG}px 0 0`},(0,v.dF)()),{"&-wrapper":{width:"100%",display:"flex",alignItems:"center"},"&-title":Object.assign(Object.assign({display:"inline-block",flex:1},v.vS),{[`
          > ${t}-typography,
          > ${t}-typography-edit-content
        `]:{insetInlineStart:0,marginTop:0,marginBottom:0}}),[`${r}-tabs-top`]:{clear:"both",marginBottom:l,color:e.colorText,fontWeight:"normal",fontSize:e.fontSize,"&-bar":{borderBottom:`${e.lineWidth}px ${e.lineType} ${e.colorBorderSecondary}`}}})},I=e=>{const{cardPaddingBase:r,colorBorderSecondary:t,cardShadow:a,lineWidth:i}=e;return{width:"33.33%",padding:r,border:0,borderRadius:0,boxShadow:`
      ${i}px 0 0 0 ${t},
      0 ${i}px 0 0 ${t},
      ${i}px ${i}px 0 0 ${t},
      ${i}px 0 0 0 ${t} inset,
      0 ${i}px 0 0 ${t} inset;
    `,transition:`all ${e.motionDurationMid}`,"&-hoverable:hover":{position:"relative",zIndex:1,boxShadow:a}}},me=e=>{const{componentCls:r,iconCls:t,actionsLiMargin:a,cardActionsIconSize:i,colorBorderSecondary:l,actionsBg:m}=e;return Object.assign(Object.assign({margin:0,padding:0,listStyle:"none",background:m,borderTop:`${e.lineWidth}px ${e.lineType} ${l}`,display:"flex",borderRadius:`0 0 ${e.borderRadiusLG}px ${e.borderRadiusLG}px `},(0,v.dF)()),{"& > li":{margin:a,color:e.colorTextDescription,textAlign:"center","> span":{position:"relative",display:"block",minWidth:e.cardActionsIconSize*2,fontSize:e.fontSize,lineHeight:e.lineHeight,cursor:"pointer","&:hover":{color:e.colorPrimary,transition:`color ${e.motionDurationMid}`},[`a:not(${r}-btn), > ${t}`]:{display:"inline-block",width:"100%",color:e.colorTextDescription,lineHeight:`${e.fontSize*e.lineHeight}px`,transition:`color ${e.motionDurationMid}`,"&:hover":{color:e.colorPrimary}},[`> ${t}`]:{fontSize:i,lineHeight:`${i*e.lineHeight}px`}},"&:not(:last-child)":{borderInlineEnd:`${e.lineWidth}px ${e.lineType} ${l}`}}})},_=e=>Object.assign(Object.assign({margin:`-${e.marginXXS}px 0`,display:"flex"},(0,v.dF)()),{"&-avatar":{paddingInlineEnd:e.padding},"&-detail":{overflow:"hidden",flex:1,"> div:not(:last-child)":{marginBottom:e.marginXS}},"&-title":Object.assign({color:e.colorTextHeading,fontWeight:e.fontWeightStrong,fontSize:e.fontSizeLG},v.vS),"&-description":{color:e.colorTextDescription}}),D=e=>{const{componentCls:r,cardPaddingBase:t,colorFillAlter:a}=e;return{[`${r}-head`]:{padding:`0 ${t}px`,background:a,"&-title":{fontSize:e.fontSize}},[`${r}-body`]:{padding:`${e.padding}px ${t}px`}}},k=e=>{const{componentCls:r}=e;return{overflow:"hidden",[`${r}-body`]:{userSelect:"none"}}},ee=e=>{const{antCls:r,componentCls:t,cardShadow:a,cardHeadPadding:i,colorBorderSecondary:l,boxShadowTertiary:m,cardPaddingBase:p,extraColor:c}=e;return{[t]:Object.assign(Object.assign({},(0,v.Wf)(e)),{position:"relative",background:e.colorBgContainer,borderRadius:e.borderRadiusLG,[`&:not(${t}-bordered)`]:{boxShadow:m},[`${t}-head`]:L(e),[`${t}-extra`]:{marginInlineStart:"auto",color:c,fontWeight:"normal",fontSize:e.fontSize},[`${t}-body`]:Object.assign({padding:p,borderRadius:` 0 0 ${e.borderRadiusLG}px ${e.borderRadiusLG}px`},(0,v.dF)()),[`${t}-grid`]:I(e),[`${t}-cover`]:{"> *":{display:"block",width:"100%"},[`img, img + ${r}-image-mask`]:{borderRadius:`${e.borderRadiusLG}px ${e.borderRadiusLG}px 0 0`}},[`${t}-actions`]:me(e),[`${t}-meta`]:_(e)}),[`${t}-bordered`]:{border:`${e.lineWidth}px ${e.lineType} ${l}`,[`${t}-cover`]:{marginTop:-1,marginInlineStart:-1,marginInlineEnd:-1}},[`${t}-hoverable`]:{cursor:"pointer",transition:`box-shadow ${e.motionDurationMid}, border-color ${e.motionDurationMid}`,"&:hover":{borderColor:"transparent",boxShadow:a}},[`${t}-contain-grid`]:{[`${t}-body`]:{display:"flex",flexWrap:"wrap"},[`&:not(${t}-loading) ${t}-body`]:{marginBlockStart:-e.lineWidth,marginInlineStart:-e.lineWidth,padding:0}},[`${t}-contain-tabs`]:{[`> ${t}-head`]:{[`${t}-head-title, ${t}-extra`]:{paddingTop:i}}},[`${t}-type-inner`]:D(e),[`${t}-loading`]:k(e),[`${t}-rtl`]:{direction:"rtl"}}},te=e=>{const{componentCls:r,cardPaddingSM:t,headerHeightSM:a,headerFontSizeSM:i}=e;return{[`${r}-small`]:{[`> ${r}-head`]:{minHeight:a,padding:`0 ${t}px`,fontSize:i,[`> ${r}-head-wrapper`]:{[`> ${r}-extra`]:{fontSize:e.fontSize}}},[`> ${r}-body`]:{padding:t}},[`${r}-small${r}-contain-tabs`]:{[`> ${r}-head`]:{[`${r}-head-title, ${r}-extra`]:{minHeight:a,paddingTop:0,display:"flex",alignItems:"center"}}}}};var ne=(0,N.Z)("Card",e=>{const r=(0,de.TS)(e,{cardShadow:e.boxShadowCard,cardHeadPadding:e.padding,cardPaddingBase:e.paddingLG,cardActionsIconSize:e.fontSize,cardPaddingSM:12});return[ee(r),te(r)]},e=>({headerBg:"transparent",headerFontSize:e.fontSizeLG,headerFontSizeSM:e.fontSize,headerHeight:e.fontSizeLG*e.lineHeightLG+e.padding*2,headerHeightSM:e.fontSize*e.lineHeight+e.paddingXS*2,actionsBg:e.colorBgContainer,actionsLiMargin:`${e.paddingSM}px 0`,tabsMarginBottom:-e.padding-e.lineWidth,extraColor:e.colorText})),A=function(e,r){var t={};for(var a in e)Object.prototype.hasOwnProperty.call(e,a)&&r.indexOf(a)<0&&(t[a]=e[a]);if(e!=null&&typeof Object.getOwnPropertySymbols=="function")for(var i=0,a=Object.getOwnPropertySymbols(e);i<a.length;i++)r.indexOf(a[i])<0&&Object.prototype.propertyIsEnumerable.call(e,a[i])&&(t[a[i]]=e[a[i]]);return t};function ae(e){return e.map((r,t)=>o.createElement("li",{style:{width:`${100/e.length}%`},key:`action-${t}`},o.createElement("span",null,r)))}var ie=o.forwardRef((e,r)=>{const{prefixCls:t,className:a,rootClassName:i,style:l,extra:m,headStyle:p={},bodyStyle:c={},title:g,loading:$,bordered:y=!0,size:u,type:h,cover:E,actions:C,tabList:x,children:f,activeTabKey:b,defaultActiveTabKey:B,tabBarExtraContent:P,hoverable:z,tabProps:R={}}=e,oe=A(e,["prefixCls","className","rootClassName","style","extra","headStyle","bodyStyle","title","loading","bordered","size","type","cover","actions","tabList","children","activeTabKey","defaultActiveTabKey","tabBarExtraContent","hoverable","tabProps"]),{getPrefixCls:le,direction:X,card:j}=o.useContext(T.E_),se=w=>{var O;(O=e.onTabChange)===null||O===void 0||O.call(e,w)},G=o.useMemo(()=>{let w=!1;return o.Children.forEach(f,O=>{O&&O.type&&O.type===q&&(w=!0)}),w},[f]),d=le("card",t),[ye,ue]=ne(d),he=o.createElement(J.Z,{loading:!0,active:!0,paragraph:{rows:4},title:!1},f),pe=b!==void 0,xe=Object.assign(Object.assign({},R),{[pe?"activeKey":"defaultActiveKey"]:pe?b:B,tabBarExtraContent:P});let be;const W=(0,M.Z)(u),Se=!W||W==="default"?"large":W,fe=x?o.createElement(Q.Z,Object.assign({size:Se},xe,{className:`${d}-head-tabs`,onChange:se,items:x.map(w=>{var{tab:O}=w,we=A(w,["tab"]);return Object.assign({label:O},we)})})):null;(g||m||fe)&&(be=o.createElement("div",{className:`${d}-head`,style:p},o.createElement("div",{className:`${d}-head-wrapper`},g&&o.createElement("div",{className:`${d}-head-title`},g),m&&o.createElement("div",{className:`${d}-extra`},m)),fe));const ve=E?o.createElement("div",{className:`${d}-cover`},E):null,Ce=o.createElement("div",{className:`${d}-body`,style:c},$?he:f),Oe=C&&C.length?o.createElement("ul",{className:`${d}-actions`},ae(C)):null,je=(0,V.Z)(oe,["onTabChange"]),Ee=S()(d,j==null?void 0:j.className,{[`${d}-loading`]:$,[`${d}-bordered`]:y,[`${d}-hoverable`]:z,[`${d}-contain-grid`]:G,[`${d}-contain-tabs`]:x&&x.length,[`${d}-${W}`]:W,[`${d}-type-${h}`]:!!h,[`${d}-rtl`]:X==="rtl"},a,i,ue),ze=Object.assign(Object.assign({},j==null?void 0:j.style),l);return ye(o.createElement("div",Object.assign({ref:r},je,{className:Ee,style:ze}),be,ve,Ce,Oe))}),F=function(e,r){var t={};for(var a in e)Object.prototype.hasOwnProperty.call(e,a)&&r.indexOf(a)<0&&(t[a]=e[a]);if(e!=null&&typeof Object.getOwnPropertySymbols=="function")for(var i=0,a=Object.getOwnPropertySymbols(e);i<a.length;i++)r.indexOf(a[i])<0&&Object.prototype.propertyIsEnumerable.call(e,a[i])&&(t[a[i]]=e[a[i]]);return t},Z=e=>{const{prefixCls:r,className:t,avatar:a,title:i,description:l}=e,m=F(e,["prefixCls","className","avatar","title","description"]),{getPrefixCls:p}=o.useContext(T.E_),c=p("card",r),g=S()(`${c}-meta`,t),$=a?o.createElement("div",{className:`${c}-meta-avatar`},a):null,y=i?o.createElement("div",{className:`${c}-meta-title`},i):null,u=l?o.createElement("div",{className:`${c}-meta-description`},l):null,h=y||u?o.createElement("div",{className:`${c}-meta-detail`},y,u):null;return o.createElement("div",Object.assign({},m,{className:g}),$,h)};const H=ie;H.Grid=q,H.Meta=Z;var n=H},38915:function($e,K,s){s.d(K,{Z:function(){return H}});var U=s(94184),S=s.n(U),V=s(50344),o=s(67294),T=s(96159),M=s(74443),J=s(53124),Q=s(98675),Y=o.createContext({}),v=n=>{let{children:e}=n;return e};function N(n){return n!=null}var L=n=>{const{itemPrefixCls:e,component:r,span:t,className:a,style:i,labelStyle:l,contentStyle:m,bordered:p,label:c,content:g,colon:$}=n,y=r;return p?o.createElement(y,{className:S()({[`${e}-item-label`]:N(c),[`${e}-item-content`]:N(g)},a),style:i,colSpan:t},N(c)&&o.createElement("span",{style:l},c),N(g)&&o.createElement("span",{style:m},g)):o.createElement(y,{className:S()(`${e}-item`,a),style:i,colSpan:t},o.createElement("div",{className:`${e}-item-container`},(c||c===0)&&o.createElement("span",{className:S()(`${e}-item-label`,{[`${e}-item-no-colon`]:!$}),style:l},c),(g||g===0)&&o.createElement("span",{className:S()(`${e}-item-content`),style:m},g)))};function I(n,e,r){let{colon:t,prefixCls:a,bordered:i}=e,{component:l,type:m,showLabel:p,showContent:c,labelStyle:g,contentStyle:$}=r;return n.map((y,u)=>{let{props:{label:h,children:E,prefixCls:C=a,className:x,style:f,labelStyle:b,contentStyle:B,span:P=1},key:z}=y;return typeof l=="string"?o.createElement(L,{key:`${m}-${z||u}`,className:x,style:f,labelStyle:Object.assign(Object.assign({},g),b),contentStyle:Object.assign(Object.assign({},$),B),span:P,colon:t,component:l,itemPrefixCls:C,bordered:i,label:p?h:null,content:c?E:null}):[o.createElement(L,{key:`label-${z||u}`,className:x,style:Object.assign(Object.assign(Object.assign({},g),f),b),span:1,colon:t,component:l[0],itemPrefixCls:C,bordered:i,label:h}),o.createElement(L,{key:`content-${z||u}`,className:x,style:Object.assign(Object.assign(Object.assign({},$),f),B),span:P*2-1,component:l[1],itemPrefixCls:C,bordered:i,content:E})]})}var _=n=>{const e=o.useContext(Y),{prefixCls:r,vertical:t,row:a,index:i,bordered:l}=n;return t?o.createElement(o.Fragment,null,o.createElement("tr",{key:`label-${i}`,className:`${r}-row`},I(a,n,Object.assign({component:"th",type:"label",showLabel:!0},e))),o.createElement("tr",{key:`content-${i}`,className:`${r}-row`},I(a,n,Object.assign({component:"td",type:"content",showContent:!0},e)))):o.createElement("tr",{key:i,className:`${r}-row`},I(a,n,Object.assign({component:l?["th","td"]:"td",type:"item",showLabel:!0,showContent:!0},e)))},D=s(14747),k=s(67968),ee=s(45503);const te=n=>{const{componentCls:e,labelBg:r}=n;return{[`&${e}-bordered`]:{[`${e}-view`]:{border:`${n.lineWidth}px ${n.lineType} ${n.colorSplit}`,"> table":{tableLayout:"auto",borderCollapse:"collapse"}},[`${e}-item-label, ${e}-item-content`]:{padding:`${n.padding}px ${n.paddingLG}px`,borderInlineEnd:`${n.lineWidth}px ${n.lineType} ${n.colorSplit}`,"&:last-child":{borderInlineEnd:"none"}},[`${e}-item-label`]:{color:n.colorTextSecondary,backgroundColor:r,"&::after":{display:"none"}},[`${e}-row`]:{borderBottom:`${n.lineWidth}px ${n.lineType} ${n.colorSplit}`,"&:last-child":{borderBottom:"none"}},[`&${e}-middle`]:{[`${e}-item-label, ${e}-item-content`]:{padding:`${n.paddingSM}px ${n.paddingLG}px`}},[`&${e}-small`]:{[`${e}-item-label, ${e}-item-content`]:{padding:`${n.paddingXS}px ${n.padding}px`}}}}},ne=n=>{const{componentCls:e,extraColor:r,itemPaddingBottom:t,colonMarginRight:a,colonMarginLeft:i,titleMarginBottom:l}=n;return{[e]:Object.assign(Object.assign(Object.assign({},(0,D.Wf)(n)),te(n)),{["&-rtl"]:{direction:"rtl"},[`${e}-header`]:{display:"flex",alignItems:"center",marginBottom:l},[`${e}-title`]:Object.assign(Object.assign({},D.vS),{flex:"auto",color:n.colorText,fontWeight:n.fontWeightStrong,fontSize:n.fontSizeLG,lineHeight:n.lineHeightLG}),[`${e}-extra`]:{marginInlineStart:"auto",color:r,fontSize:n.fontSize},[`${e}-view`]:{width:"100%",borderRadius:n.borderRadiusLG,table:{width:"100%",tableLayout:"fixed"}},[`${e}-row`]:{"> th, > td":{paddingBottom:t},"&:last-child":{borderBottom:"none"}},[`${e}-item-label`]:{color:n.colorTextTertiary,fontWeight:"normal",fontSize:n.fontSize,lineHeight:n.lineHeight,textAlign:"start","&::after":{content:'":"',position:"relative",top:-.5,marginInline:`${i}px ${a}px`},[`&${e}-item-no-colon::after`]:{content:'""'}},[`${e}-item-no-label`]:{"&::after":{margin:0,content:'""'}},[`${e}-item-content`]:{display:"table-cell",flex:1,color:n.colorText,fontSize:n.fontSize,lineHeight:n.lineHeight,wordBreak:"break-word",overflowWrap:"break-word"},[`${e}-item`]:{paddingBottom:0,verticalAlign:"top","&-container":{display:"flex",[`${e}-item-label`]:{display:"inline-flex",alignItems:"baseline"},[`${e}-item-content`]:{display:"inline-flex",alignItems:"baseline"}}},"&-middle":{[`${e}-row`]:{"> th, > td":{paddingBottom:n.paddingSM}}},"&-small":{[`${e}-row`]:{"> th, > td":{paddingBottom:n.paddingXS}}}})}};var A=(0,k.Z)("Descriptions",n=>{const e=(0,ee.TS)(n,{});return[ne(e)]},n=>({labelBg:n.colorFillAlter,titleMarginBottom:n.fontSizeSM*n.lineHeightSM,itemPaddingBottom:n.padding,colonMarginRight:n.marginXS,colonMarginLeft:n.marginXXS/2,extraColor:n.colorText})),ae=function(n,e){var r={};for(var t in n)Object.prototype.hasOwnProperty.call(n,t)&&e.indexOf(t)<0&&(r[t]=n[t]);if(n!=null&&typeof Object.getOwnPropertySymbols=="function")for(var a=0,t=Object.getOwnPropertySymbols(n);a<t.length;a++)e.indexOf(t[a])<0&&Object.prototype.propertyIsEnumerable.call(n,t[a])&&(r[t[a]]=n[t[a]]);return r};const re={xxl:3,xl:3,lg:3,md:3,sm:2,xs:1};function ie(n,e){if(typeof n=="number")return n;if(typeof n=="object")for(let r=0;r<M.c.length;r++){const t=M.c[r];if(e[t]&&n[t]!==void 0)return n[t]||re[t]}return 3}function F(n,e,r){let t=n;return(r===void 0||r>e)&&(t=(0,T.Tm)(n,{span:e})),t}function ge(n,e){const r=(0,V.Z)(n).filter(l=>l),t=[];let a=[],i=e;return r.forEach((l,m)=>{var p;const c=(p=l.props)===null||p===void 0?void 0:p.span,g=c||1;if(m===r.length-1){a.push(F(l,i,c)),t.push(a);return}g<i?(i-=g,a.push(l)):(a.push(F(l,i,g)),t.push(a),i=e,a=[])}),t}const Z=n=>{const{prefixCls:e,title:r,extra:t,column:a=re,colon:i=!0,bordered:l,layout:m,children:p,className:c,rootClassName:g,style:$,size:y,labelStyle:u,contentStyle:h}=n,E=ae(n,["prefixCls","title","extra","column","colon","bordered","layout","children","className","rootClassName","style","size","labelStyle","contentStyle"]),{getPrefixCls:C,direction:x,descriptions:f}=o.useContext(J.E_),b=C("descriptions",e),[B,P]=o.useState({}),z=ie(a,B),R=(0,Q.Z)(y),[oe,le]=A(b),X=(0,M.Z)();o.useEffect(()=>{const G=X.subscribe(d=>{typeof a=="object"&&P(d)});return()=>{X.unsubscribe(G)}},[]);const j=ge(p,z),se=o.useMemo(()=>({labelStyle:u,contentStyle:h}),[u,h]);return oe(o.createElement(Y.Provider,{value:se},o.createElement("div",Object.assign({className:S()(b,f==null?void 0:f.className,{[`${b}-${R}`]:R&&R!=="default",[`${b}-bordered`]:!!l,[`${b}-rtl`]:x==="rtl"},c,g,le),style:Object.assign(Object.assign({},f==null?void 0:f.style),$)},E),(r||t)&&o.createElement("div",{className:`${b}-header`},r&&o.createElement("div",{className:`${b}-title`},r),t&&o.createElement("div",{className:`${b}-extra`},t)),o.createElement("div",{className:`${b}-view`},o.createElement("table",null,o.createElement("tbody",null,j.map((G,d)=>o.createElement(_,{key:d,index:d,colon:i,prefixCls:b,vertical:m==="vertical",bordered:l,row:G}))))))))};Z.Item=v;var H=Z}}]);