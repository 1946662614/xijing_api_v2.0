"use strict";(self.webpackChunkant_design_pro=self.webpackChunkant_design_pro||[]).push([[191],{59481:function(P,i,t){t.r(i),t.d(i,{default:function(){return G}});var c=t(5574),u=t.n(c),g=t(90930),e=t(67294),h=t(39048),m=t(15009),f=t.n(m),p=t(97857),y=t.n(p),I=t(99289),T=t.n(I),S=t(35312);function j(s){return r.apply(this,arguments)}function r(){return r=T()(f()().mark(function s(o){return f()().wrap(function(n){for(;;)switch(n.prev=n.next){case 0:return n.abrupt("return",(0,S.request)("/api/analysis/top/interface/invoke",y()({method:"GET"},o||{})));case 1:case"end":return n.stop()}},s)})),r.apply(this,arguments)}var d=t(85893),A=function(){var o=(0,e.useState)([]),l=u()(o,2),n=l[0],x=l[1],C=(0,e.useState)(!0),v=u()(C,2),E=v[0],D=v[1];(0,e.useEffect)(function(){try{j().then(function(a){a.data&&(x(a.data),D(!1))})}catch(a){console.log(a)}},[]);var L=n.map(function(a){return{name:a.name,value:a.totalNum}}),O={title:{text:"\u8C03\u7528\u6B21\u6570\u7EDF\u8BA1",subtext:"TOP3",left:"center"},tooltip:{trigger:"item"},legend:{orient:"vertical",left:"left"},series:[{name:"\u8C03\u7528\u6B21\u6570",type:"pie",radius:"50%",data:L,emphasis:{itemStyle:{shadowBlur:10,shadowOffsetX:0,shadowColor:"rgba(0, 0, 0, 0.5)"}}}]};return(0,d.jsx)(g._z,{children:(0,d.jsx)(h.Z,{showLoading:E,option:O})})},G=A}}]);