(self.webpackChunkHcsImageViewer=self.webpackChunkHcsImageViewer||[]).push([[822],{2061:function(e,t,r){"use strict";r.r(t),r.d(t,{default:function(){return Fe}});var n=r(7462),o=r(7294),i=r(3935),a=r(4942),c=r(885),s=r(5697),u=r.n(s),l=r(3238),f="set-data",d="set-source-initializing",p="set-source",v="set-source-error",m="set-image",b="set-image-viewport-loaded";function h(e,t){var r=Object.keys(e);if(Object.getOwnPropertySymbols){var n=Object.getOwnPropertySymbols(e);t&&(n=n.filter((function(t){return Object.getOwnPropertyDescriptor(e,t).enumerable}))),r.push.apply(r,n)}return r}function y(e){for(var t=1;t<arguments.length;t++){var r=null!=arguments[t]?arguments[t]:{};t%2?h(Object(r),!0).forEach((function(t){(0,a.Z)(e,t,r[t])})):Object.getOwnPropertyDescriptors?Object.defineProperties(e,Object.getOwnPropertyDescriptors(r)):h(Object(r)).forEach((function(t){Object.defineProperty(e,t,Object.getOwnPropertyDescriptor(r,t))}))}return e}function g(e,t){var r=Object.keys(e);if(Object.getOwnPropertySymbols){var n=Object.getOwnPropertySymbols(e);t&&(n=n.filter((function(t){return Object.getOwnPropertyDescriptor(e,t).enumerable}))),r.push.apply(r,n)}return r}function O(e){for(var t=1;t<arguments.length;t++){var r=null!=arguments[t]?arguments[t]:{};t%2?g(Object(r),!0).forEach((function(t){(0,a.Z)(e,t,r[t])})):Object.getOwnPropertyDescriptors?Object.defineProperties(e,Object.getOwnPropertyDescriptors(r)):g(Object(r)).forEach((function(t){Object.defineProperty(e,t,Object.getOwnPropertyDescriptor(r,t))}))}return e}function w(e,t){var r=Object.keys(e);if(Object.getOwnPropertySymbols){var n=Object.getOwnPropertySymbols(e);t&&(n=n.filter((function(t){return Object.getOwnPropertyDescriptor(e,t).enumerable}))),r.push.apply(r,n)}return r}function j(e){for(var t=1;t<arguments.length;t++){var r=null!=arguments[t]?arguments[t]:{};t%2?w(Object(r),!0).forEach((function(t){(0,a.Z)(e,t,r[t])})):Object.getOwnPropertyDescriptors?Object.defineProperties(e,Object.getOwnPropertyDescriptors(r)):w(Object(r)).forEach((function(t){Object.defineProperty(e,t,Object.getOwnPropertyDescriptor(r,t))}))}return e}var P=function(e,t){switch(t.type){case f:return function(e,t){var r=t.url,n=t.offsetsUrl,o=t.callback,i=e.url,a=e.offsetsUrl;return i===r&&n===a?(o&&o(),e):y(y({},e),{},{loader:void 0,metadata:void 0,imageIndex:0,imageTimePosition:0,source:void 0,sourcePending:!1,sourceError:!1,sourceCallback:o,error:void 0,url:r,offsetsUrl:n})}(e,t);case"set-error":return function(e,t){var r=t.error;return O(O({},e),{},{error:r})}(e,t);case d:return function(e){return j(j({},e),{},{loader:void 0,metadata:void 0,imageIndex:0,source:void 0,sourceError:void 0,sourcePending:!0,imagePending:!1})}(e);case v:return function(e,t){var r=t.error,n=e.sourceCallback;return"function"==typeof n&&setTimeout((function(){n({error:r})}),0),j(j({},e),{},{loader:void 0,metadata:void 0,imageIndex:0,source:void 0,sourceError:r,sourcePending:!1,sourceCallback:void 0})}(e,t);case p:return function(e,t){var r=t.source,n=e.sourceCallback;"function"==typeof n&&setTimeout((function(){n()}),0);var o=Array.isArray(r)?r:[r],i=o.map((function(e){return e.data})),a=o.map((function(e){return e.metadata}));return j(j({},e),{},{loader:i,metadata:a,imageIndex:0,source:r,sourceError:void 0,sourcePending:!1,sourceCallback:void 0})}(e,t);case m:return function(e,t){var r,n=t.index,o=t.ID,i=t.Name,a=t.search,s=t.imageTimePosition,u=void 0===s?0:s,l=e.metadata,f=void 0===l?[]:l;if(null!=n)r=f[n];else if(void 0!==o)r=f.find((function(e){return e.ID===o}));else if(void 0!==i)r=f.find((function(e){return(e.Name||e.name||"").toLowerCase()===i.toLowerCase()}));else if(a&&/^[\d]+_[\d]+$/.test(a)){var d=/^([\d]+)_([\d])+$/.exec(a),p=(0,c.Z)(d,3),v=p[1],m=p[2],b=new RegExp("^\\s*well\\s+".concat(v,"\\s*,\\s*field\\s+").concat(m,"\\s*$"),"i");r=f.find((function(e){return b.test(e.Name||e.name)}))}if(r){var h=f.indexOf(r);return j(j({},e),{},{imageIndex:h,imagePending:!0,imageTimePosition:u})}return e}(e,t);case b:return function(e){return j(j({},e),{},{imagePending:!1})}(e);default:return e}},x=r(5861),S=r(3144),Z=r(5671),k=r(136),C=r(4575),D=r(1120),E=r(2407),z=r(7757),L=r.n(z),M=r(265);var I=function(e){(0,k.Z)(o,e);var t,r,n=(t=o,r=function(){if("undefined"==typeof Reflect||!Reflect.construct)return!1;if(Reflect.construct.sham)return!1;if("function"==typeof Proxy)return!0;try{return Boolean.prototype.valueOf.call(Reflect.construct(Boolean,[],(function(){}))),!0}catch(e){return!1}}(),function(){var e,n=(0,D.Z)(t);if(r){var o=(0,D.Z)(this).constructor;e=Reflect.construct(n,arguments,o)}else e=n.apply(this,arguments);return(0,C.Z)(this,e)});function o(e){var t;return(0,Z.Z)(this,o),t=e?n.call(this,"offsets.json file not found: ".concat(e)):n.call(this,"offsets.json file not specified"),(0,C.Z)(t)}return(0,S.Z)(o)}((0,E.Z)(Error));function R(e,t,r){return A.apply(this,arguments)}function A(){return(A=(0,x.Z)(L().mark((function e(t,r,n){var o,i,a,c,s,u,l,f,d;return L().wrap((function(e){for(;;)switch(e.prev=e.next){case 0:return e.next=2,(0,M.W0)(t);case 2:return i=e.sent,e.next=5,i.getImage(0);case 5:if(a=e.sent,!Boolean(null==a||null===(o=a.fileDirectory)||void 0===o?void 0:o.SubIFDs)){e.next=9;break}return e.abrupt("return",r.reduce((function(e,t){var r=t.Pixels;return r.SizeC*r.SizeT*r.SizeZ+e}),1));case 9:return c=n[0].length,s=r[0].Pixels,u=s.SizeC,l=s.SizeT,f=s.SizeZ,d=u*l*f,e.abrupt("return",d*c);case 13:case"end":return e.stop()}}),e)})))).apply(this,arguments)}function V(){return V=(0,x.Z)(L().mark((function e(){var t,r,n,o,i,a,c,s=arguments;return L().wrap((function(e){for(;;)switch(e.prev=e.next){case 0:if(t=s.length>0&&void 0!==s[0]?s[0]:{},r=t.url,!(n=t.offsetsUrl)){e.next=8;break}return e.next=5,fetch(n);case 5:e.t0=e.sent,e.next=9;break;case 8:e.t0=void 0;case 9:if(o=e.t0,i=!o||!o.ok){e.next=17;break}return e.next=14,o.json();case 14:e.t1=e.sent,e.next=18;break;case 17:e.t1=void 0;case 18:return a=e.t1,e.next=21,(0,l.$L)(r,{offsets:a,images:"all"});case 21:if(c=e.sent,!i){e.next=28;break}return e.next=25,R(r,c.map((function(e){return e.metadata})),c.map((function(e){return e.data})));case 25:if(!(e.sent>40)){e.next=28;break}throw new I(n);case 28:return e.abrupt("return",c);case 29:case"end":return e.stop()}}),e)}))),V.apply(this,arguments)}var B="set-default",T="set-loading",N="set-error",U="set-channel-properties",F="set-color-map",G="set-lens-channel",$="set-lens-enabled",H="set-global-position";function W(){var e=[];return{identifiers:[],channels:[],channelsVisibility:[],selections:e,builtForSelections:e,globalSelection:void 0,colors:[],domains:[],contrastLimits:[],useLens:!1,useColorMap:!1,colorMap:"",lensEnabled:!1,lensChannel:0,use3D:!1,pixelValues:[],xSlice:[0,1],ySlice:[0,1],zSlice:[0,1],ready:!1,isRGB:!1,shapeIsInterleaved:!1,pending:!1,globalDimensions:[],metadata:void 0,loader:[],error:void 0}}var _=r(2982);function q(e,t){var r=Object.keys(e);if(Object.getOwnPropertySymbols){var n=Object.getOwnPropertySymbols(e);t&&(n=n.filter((function(t){return Object.getOwnPropertyDescriptor(e,t).enumerable}))),r.push.apply(r,n)}return r}var J=r(4477);function K(e,t){var r=Object.keys(e);if(Object.getOwnPropertySymbols){var n=Object.getOwnPropertySymbols(e);t&&(n=n.filter((function(t){return Object.getOwnPropertyDescriptor(e,t).enumerable}))),r.push.apply(r,n)}return r}function Q(e){for(var t=1;t<arguments.length;t++){var r=null!=arguments[t]?arguments[t]:{};t%2?K(Object(r),!0).forEach((function(t){(0,a.Z)(e,t,r[t])})):Object.getOwnPropertyDescriptors?Object.defineProperties(e,Object.getOwnPropertyDescriptors(r)):K(Object(r)).forEach((function(t){Object.defineProperty(e,t,Object.getOwnPropertyDescriptor(r,t))}))}return e}var X=[],Y=[0,1];function ee(e,t){switch(t.type){case T:return Q(Q({},e),{},{pending:!0,error:void 0});case U:return function(e,t,r){var n=Object.entries(r||{}).filter((function(t){var r=(0,c.Z)(t,1)[0];return e&&e[r]&&Array.isArray(e[r])}));if(n.length>0){var o=function(e){for(var t=1;t<arguments.length;t++){var r=null!=arguments[t]?arguments[t]:{};t%2?q(Object(r),!0).forEach((function(t){(0,a.Z)(e,t,r[t])})):Object.getOwnPropertyDescriptors?Object.defineProperties(e,Object.getOwnPropertyDescriptors(r)):q(Object(r)).forEach((function(t){Object.defineProperty(e,t,Object.getOwnPropertyDescriptor(r,t))}))}return e}({},e||{});return n.forEach((function(e){var r=(0,c.Z)(e,2),n=r[0],i=r[1],a=o[n];o[n]=(0,_.Z)(a),o[n][t]=i})),o}return e}(e,t.channel,t.properties);case F:var r=t.colorMap,n=void 0===r?"":r;return e.useColorMap?Q(Q({},e),{},{colorMap:n}):e;case G:var o=t.lensChannel,i=void 0===o?0:o,s=e.lensEnabled,u=e.useLens;return s&&u?Q(Q({},e),{},{lensChannel:i}):e;case $:var l=t.lensEnabled,f=void 0!==l&&l,d=e.lensEnabled,p=e.useLens;return Q(Q({},e),{},p&&!d&&f?{lensEnabled:f,lensChannel:0}:{lensEnabled:!1});case H:var v=t.position,m=void 0===v?{}:v,b=e.globalDimensions,h=void 0===b?[]:b,y=e.selections,g=void 0===y?[]:y,O=e.globalSelection,w=void 0===O?{}:O,j=function(e,t){var r=(h.find((function(t){return t.label===e}))||{}).size,n=void 0===r?0:r;return Math.max(0,Math.min(n,Math.round(t)))},P=Object.entries(m).filter((function(e){var t=(0,c.Z)(e,1)[0];return J.Z.includes(t)&&h.find((function(e){return e.label===t}))})).map((function(e){var t=(0,c.Z)(e,2),r=t[0],n=t[1];return{dimension:r,position:j(r,n)}}));if(P.length>0){var x=P.map((function(e){var t=e.dimension,r=e.position;return(0,a.Z)({},t,r)})).reduce((function(e,t){return Q(Q({},e),t)}),{}),S=Q(Q({},w),x),Z=g.map((function(e){return Q(Q({},e),x)}));return Q(Q({},e),{},{selections:Z,globalSelection:S})}return e;case B:var k=t.identifiers,C=void 0===k?X:k,D=t.channels,E=void 0===D?X:D,z=t.selections,L=void 0===z?X:z,M=t.colors,I=void 0===M?X:M,R=t.domains,A=void 0===R?X:R,V=t.contrastLimits,W=void 0===V?X:V,K=t.useLens,ee=void 0!==K&&K,te=t.useColorMap,re=void 0!==te&&te,ne=t.colorMap,oe=void 0===ne?re?e.colorMap:"":ne,ie=t.lensEnabled,ae=void 0!==ie&&ie,ce=t.lensChannel,se=void 0===ce?0:ce,ue=t.xSlice,le=void 0===ue?Y:ue,fe=t.ySlice,de=void 0===fe?Y:fe,pe=t.zSlice,ve=void 0===pe?Y:pe,me=t.use3D,be=void 0!==me&&me,he=t.ready,ye=void 0!==he&&he,ge=t.isRGB,Oe=void 0!==ge&&ge,we=t.shapeIsInterleaved,je=void 0!==we&&we,Pe=t.globalDimensions,xe=void 0===Pe?X:Pe,Se=t.metadata,Ze=t.loader;return{identifiers:C,channels:E,channelsVisibility:E.map((function(){return!0})),selections:L,builtForSelections:L,globalSelection:(L||[])[0],pixelValues:new Array((L||[]).length).fill("-----"),colors:I,domains:A,contrastLimits:W,useLens:ee,useColorMap:re,colorMap:oe,lensEnabled:ae,lensChannel:se,xSlice:le,ySlice:de,zSlice:ve,use3D:be,ready:ye,isRGB:Oe,shapeIsInterleaved:je,globalDimensions:xe,pending:!1,error:void 0,metadata:Se,loader:Ze};case N:var ke=t.error;return Q(Q({},e),{},{error:ke,pending:!1});default:return e}}var te=r(3467);function re(e){var t=e[e.length-1];return 3===t||4===t}function ne(e,t){var r=Object.keys(e);if(Object.getOwnPropertySymbols){var n=Object.getOwnPropertySymbols(e);t&&(n=n.filter((function(t){return Object.getOwnPropertyDescriptor(e,t).enumerable}))),r.push.apply(r,n)}return r}function oe(e){for(var t=1;t<arguments.length;t++){var r=null!=arguments[t]?arguments[t]:{};t%2?ne(Object(r),!0).forEach((function(t){(0,a.Z)(e,t,r[t])})):Object.getOwnPropertyDescriptors?Object.defineProperties(e,Object.getOwnPropertyDescriptors(r)):ne(Object(r)).forEach((function(t){Object.defineProperty(e,t,Object.getOwnPropertyDescriptor(r,t))}))}return e}function ie(e,t){for(var r=[],n=oe(oe({},function(e){var t=arguments.length>1&&void 0!==arguments[1]?arguments[1]:J.Z;return e.labels.filter((function(e){return t.includes(e)})).map((function(e){return(0,a.Z)({},e,0)})).reduce((function(e,t){return oe(oe({},e),t)}),{})}(e)),t||{}),o=e.labels.map((function(t,r){return{name:t,size:e.shape[r]}})).find((function(e){return!J.Z.includes(e.name)&&e.size})),i=0;i<Math.min(4,o.size);i+=1)r.push(oe((0,a.Z)({},o.name,i),n));return re(e.shape)?[oe(oe({},r[0]),{},{c:0})]:r}function ae(e){return ce.apply(this,arguments)}function ce(){return(ce=(0,x.Z)(L().mark((function e(t){var r,n,o,i,a,c,s;return L().wrap((function(e){for(;;)switch(e.prev=e.next){case 0:return r=t.loader,n=t.selection,o=Array.isArray(r)?r[r.length-1]:r,e.next=4,o.getRaster({selection:n});case 4:return i=e.sent,a=(0,l.mx)(i.data),c=a.domain,s=a.contrastLimits,e.abrupt("return",{domain:c,contrastLimits:s});case 8:case"end":return e.stop()}}),e)})))).apply(this,arguments)}function se(e){return ue.apply(this,arguments)}function ue(){return(ue=(0,x.Z)(L().mark((function e(t){var r,n,o,i,a,c,s,u,f,d,p,v;return L().wrap((function(e){for(;;)switch(e.prev=e.next){case 0:return r=t.loader,n=t.selection,o=r[r.length-1],i=o.shape,a=o.labels,c=i[a.indexOf("z")]>>r.length-1,e.next=6,o.getRaster({selection:oe(oe({},n),{},{z:0})});case 6:return s=e.sent,e.next=9,o.getRaster({selection:oe(oe({},n),{},{z:Math.floor(c/2)})});case 9:return u=e.sent,e.next=12,o.getRaster({selection:oe(oe({},n),{},{z:Math.max(0,c-1)})});case 12:return f=e.sent,d=(0,l.mx)(s.data),p=(0,l.mx)(u.data),v=(0,l.mx)(f.data),e.abrupt("return",{domain:[Math.min(d.domain[0],p.domain[0],v.domain[0]),Math.max(d.domain[1],p.domain[1],v.domain[1])],contrastLimits:[Math.min(d.contrastLimits[0],p.contrastLimits[0],v.contrastLimits[0]),Math.max(d.contrastLimits[1],p.contrastLimits[1],v.contrastLimits[1])]});case 17:case"end":return e.stop()}}),e)})))).apply(this,arguments)}function le(e){return fe.apply(this,arguments)}function fe(){return(fe=(0,x.Z)(L().mark((function e(t){var r,n,o,i;return L().wrap((function(e){for(;;)switch(e.prev=e.next){case 0:return r=t.loader,n=t.selection,o=t.use3d,i=o?se:ae,e.abrupt("return",i({loader:r,selection:n}));case 3:case"end":return e.stop()}}),e)})))).apply(this,arguments)}function de(e){return pe.apply(this,arguments)}function pe(){return(pe=(0,x.Z)(L().mark((function e(t){var r,n,o,i,a,c;return L().wrap((function(e){for(;;)switch(e.prev=e.next){case 0:return r=t.loader,n=t.selections,o=t.use3d,e.next=3,Promise.all(n.map((function(e){return le({loader:r,selection:e,use3d:o})})));case 3:return i=e.sent,a=i.map((function(e){return e.domain})),c=i.map((function(e){return e.contrastLimits})),e.abrupt("return",{domains:a,contrastLimits:c});case 7:case"end":return e.stop()}}),e)})))).apply(this,arguments)}function ve(e){var t=Array.isArray(e)?e[0]:e,r=t.shape,n=t.labels,o=function(e){var t,r,n=null!==(t=null==e||null===(r=e.meta)||void 0===r?void 0:r.physicalSizes)&&void 0!==t?t:{},o=n.x,i=n.y,a=n.z;if(null!=o&&o.size&&null!=i&&i.size&&null!=a&&a.size){var c=Math.min(a.size,o.size,i.size),s=[o.size/c,i.size/c,a.size/c];return(new te.Z).scale(s)}return(new te.Z).identity()}(t);return[[0,o[0]*r[n.indexOf("x")]],[0,o[5]*r[n.indexOf("y")]],[0,o[10]*r[n.indexOf("z")]]]}function me(e){var t=e.Pixels||{},r=t.Channels,n=void 0===r?[]:r,o=t.SizeC,i=void 0===o?0:o,a=t.Interleaved,c=void 0!==a&&a,s=t.Type,u=n.length,l=(n[0]||{}).SamplesPerPixel;return 3===(void 0===l?0:l)||3===u&&"uint8"===s||3===i&&1===u&&c}var be=[255,0,0],he=[0,255,0],ye=[0,0,255],ge=[255,255,255],Oe=[ye,he,[255,0,255],[255,255,0],[255,60,0],[154,0,255],ge,be],we=[0,255];function je(e,t){return e.Name||e.name||e.ID||"Channel ".concat(t+1)}function Pe(e,t,r,n){return xe.apply(this,arguments)}function xe(){return(xe=(0,x.Z)(L().mark((function e(t,r,n,o){var i,a,s,u,l,f,d,p,v,m,b,h,y,g,O,w,j,P,x,S,Z,k;return L().wrap((function(e){for(;;)switch(e.prev=e.next){case 0:if(i=t[0]||{},a=i.shape,s=i.labels,u=(void 0===s?[]:s).map((function(e,t){return{label:e,size:a[t]||0}})).filter((function(e){return e.size>1&&J.Z.includes(e.label)})),l=n||ie(t[0],o),f=r.Pixels,d=(void 0===f?{}:f).Channels,p=void 0===d?[]:d,v=[],m=[],b=[],h=!1,y=!1,g=me(r),O=g&&re(a),!g){e.next=18;break}re(a)?(v=[we.slice()],b=[we.slice()],m=[be]):(v=[we.slice(),we.slice(),we.slice()],b=[we.slice(),we.slice(),we.slice()],m=[be,he,ye]),h=!1,y=!1,e.next=26;break;case 18:return e.next=20,de({loader:t,selections:l,use3d:!1});case 20:w=e.sent,b=w.domains.slice(),v=w.contrastLimits.slice(),m=1===w.domains.length?[ge]:w.domains.map((function(e,t){return Oe[t]})),h=p.length>1,y=!0;case 26:return j=p.map(je),P=ve(t),x=(0,c.Z)(P,3),S=x[0],Z=x[1],k=x[2],e.abrupt("return",{identifiers:j.map((function(e,t){return"".concat(e||"channel","-").concat(t)})),channels:j,selections:l,useLens:h,useColorMap:y,colors:m,domains:b,contrastLimits:v,xSlice:S,ySlice:Z,zSlice:k,ready:!0,isRGB:g,shapeIsInterleaved:O,globalDimensions:u,metadata:r,loader:t});case 29:case"end":return e.stop()}}),e)})))).apply(this,arguments)}function Se(e,t){var r=Object.keys(e);if(Object.getOwnPropertySymbols){var n=Object.getOwnPropertySymbols(e);t&&(n=n.filter((function(t){return Object.getOwnPropertyDescriptor(e,t).enumerable}))),r.push.apply(r,n)}return r}function Ze(e){for(var t=1;t<arguments.length;t++){var r=null!=arguments[t]?arguments[t]:{};t%2?Se(Object(r),!0).forEach((function(t){(0,a.Z)(e,t,r[t])})):Object.getOwnPropertyDescriptors?Object.defineProperties(e,Object.getOwnPropertyDescriptors(r)):Se(Object(r)).forEach((function(t){Object.defineProperty(e,t,Object.getOwnPropertyDescriptor(r,t))}))}return e}function ke(e,t,r){var n=arguments.length>3&&void 0!==arguments[3]?arguments[3]:{},i=n.selections,a=n.cache,c=n.imageTimePosition,s=void 0===c?0:c,u=(0,o.useRef)(0);(0,o.useEffect)((function(){var n=e&&t&&e.Pixels&&t.length;if(n&&(i&&i!==a||!i)){r({type:T}),u.current+=1;var o=u.current;Pe(t,e,i,s?{t:s}:void 0).then((function(e){o===u.current&&r(Ze({type:B},e))})).catch((function(e){console.warn("HCS Image Viewer error: ".concat(e.message)),console.error(e),r({type:N,error:e.message})}))}else n||r({type:B})}),[e,t,s,i,a,u,r])}var Ce={url:void 0,offsetsUrl:void 0,source:void 0,sourcePending:!1,sourceError:void 0,sourceCallback:void 0,loader:void 0,metadata:void 0,imageIndex:0,imagePending:!1,imageTimePosition:0,error:void 0,pending:!1},De=o.createContext(Ce);function Ee(e,t){var r=Object.keys(e);if(Object.getOwnPropertySymbols){var n=Object.getOwnPropertySymbols(e);t&&(n=n.filter((function(t){return Object.getOwnPropertyDescriptor(e,t).enumerable}))),r.push.apply(r,n)}return r}function ze(e){for(var t=1;t<arguments.length;t++){var r=null!=arguments[t]?arguments[t]:{};t%2?Ee(Object(r),!0).forEach((function(t){(0,a.Z)(e,t,r[t])})):Object.getOwnPropertyDescriptors?Object.defineProperties(e,Object.getOwnPropertyDescriptors(r)):Ee(Object(r)).forEach((function(t){Object.defineProperty(e,t,Object.getOwnPropertyDescriptor(r,t))}))}return e}function Le(){return{}}function Me(){var e=(0,o.useReducer)(P,{},Le),t=(0,c.Z)(e,2),r=t[0],n=t[1];!function(e,t){var r=e||{},n=r.url,i=r.offsetsUrl,a=r.source;(0,o.useEffect)((function(){n&&(t({type:d}),function(){return V.apply(this,arguments)}({url:n,offsetsUrl:i}).then((function(e){return t({type:p,source:e})})).catch((function(e){return t({type:v,error:e.message})})))}),[n,i,t])}(r,n);var i=function(e){var t=(0,o.useReducer)(ee,{},W),r=(0,c.Z)(t,2),n=r[0],i=r[1],a=function(e){var t=e.imageIndex,r=void 0===t?0:t,n=e.metadata,o=void 0===n?[]:n;if(!(r<0||r>=o.length))return o[r]}(e),s=function(e){var t=e.imageIndex,r=void 0===t?0:t,n=e.loader,o=void 0===n?[]:n;if(!(r<0||r>=o.length))return o[r]}(e),u=e.imageTimePosition,l=void 0===u?0:u,f=n.metadata,d=n.loader,p=n.selections,v=n.builtForSelections;return ke(a,s,i,(0,o.useMemo)((function(){return{imageTimePosition:l}}),[l])),ke(f,d,i,(0,o.useMemo)((function(){return{selections:p,cache:v}}),[p,v])),{state:n,dispatch:i}}(r),a=i.state,s=i.dispatch,u=(0,o.useCallback)((function(e,t,r){n({url:e,offsetsUrl:t,callback:r,type:f})}),[n]),l=(0,o.useCallback)((function(e){n(ze({type:m},e))}),[n]),h=(0,o.useCallback)((function(e){n(ze({type:b},e))}),[n]),y=(0,o.useCallback)((function(e,t){s({type:U,channel:e,properties:t})}),[s]),g=(0,o.useCallback)((function(e){s({type:F,colorMap:e})}),[s]),O=(0,o.useCallback)((function(e){s({type:$,lensEnabled:e})}),[s]),w=(0,o.useCallback)((function(e){s({type:G,lensChannel:e})}),[s]),j=(0,o.useCallback)((function(e){s({type:H,position:e})}),[s]);return{callbacks:(0,o.useMemo)((function(){return{setData:u,setImage:l,setImageViewportLoaded:h,setChannelProperties:y,setColorMap:g,setLensEnabled:O,setLensChannel:w,setGlobalPosition:j}}),[u,l,h,y,g,O,w,j]),dispatch:n,state:r,viewerState:a,viewerDispatch:s}}function Ie(e){if(e&&e.shape){var t=re(e.shape),r=e.shape.slice(t?-3:-2),n=(0,c.Z)(r,2);return{height:n[0],width:n[1]}}}function Re(e,t){var r=arguments.length>2&&void 0!==arguments[2]?arguments[2]:0,n=Array.isArray(e)?e[0]:e,o=Ie(n);if(o&&t){var i=o.width,a=o.height;return Math.log2(Math.min(t.width/i,t.height/a))-r}return-1/0}function Ae(e,t){var r=Object.keys(e);if(Object.getOwnPropertySymbols){var n=Object.getOwnPropertySymbols(e);t&&(n=n.filter((function(t){return Object.getOwnPropertyDescriptor(e,t).enumerable}))),r.push.apply(r,n)}return r}function Ve(e){for(var t=1;t<arguments.length;t++){var r=null!=arguments[t]?arguments[t]:{};t%2?Ae(Object(r),!0).forEach((function(t){(0,a.Z)(e,t,r[t])})):Object.getOwnPropertyDescriptors?Object.defineProperties(e,Object.getOwnPropertyDescriptors(r)):Ae(Object(r)).forEach((function(t){Object.defineProperty(e,t,Object.getOwnPropertyDescriptor(r,t))}))}return e}var Be=new l.$h,Te=new l.z6;function Ne(e){var t=e.className,r=e.onStateChange,n=e.onRegisterStateActions,i=e.onViewerStateChanged,a=e.style,s=e.minZoomBackOff,u=void 0===s?0:s,f=e.maxZoomBackOff,d=void 0===f?void 0:f,p=e.defaultZoomBackOff,v=void 0===p?0:p,m=e.overview,b=Me(),h=b.state,y=b.viewerState,g=b.callbacks,O=(0,o.useRef)(),w=function(e){var t=(0,o.useState)({width:void 0,height:void 0}),r=(0,c.Z)(t,2),n=r[0],i=r[1];return(0,o.useEffect)((function(){var t,r,n;return function o(){var a,c,s=null==e||null===(a=e.current)||void 0===a?void 0:a.clientWidth,u=null==e||null===(c=e.current)||void 0===c?void 0:c.clientHeight;e&&e.current&&(s!==t||u!==r)&&i({width:t=s,height:r=u}),n=requestAnimationFrame(o)}(),function(){return cancelAnimationFrame(n)}}),[e,i]),n}(O);(0,o.useEffect)((function(){r&&r(h)}),[h,r]),(0,o.useEffect)((function(){i&&i(y)}),[y,i]),(0,o.useEffect)((function(){n&&n(g)}),[g,n]);var j=(g||{}).setImageViewportLoaded,P=y.channelsVisibility,x=void 0===P?[]:P,S=y.contrastLimits,Z=void 0===S?[]:S,k=y.colors,C=void 0===k?[]:k,D=y.selections,E=void 0===D?[]:D,z=y.ready,L=void 0!==z&&z,M=y.colorMap,I=y.loader,R=y.useLens,A=y.lensEnabled,V=y.lensChannel,B=(0,o.useState)(void 0),T=(0,c.Z)(B,2),N=T[0],U=T[1];(0,o.useEffect)((function(){if(I&&I.length&&w&&w.width&&w.height){var e=Array.isArray(I)?I:[I],t=(0,c.Z)(e,1)[0],r=Array.isArray(I)?I[I.length-1]:I,n=[Ve(Ve({},(0,l.TI)(I,w,v)),{},{id:l.ys,minZoom:void 0!==u?Re(t,w,u):-1/0,maxZoom:void 0!==d?Re(r,w,d):1/0})];U(n)}else U(void 0)}),[I,w,U,u,d,v]);var F=I&&L&&w&&w.width&&w.height&&N;return o.createElement(De.Provider,{value:h},o.createElement("div",{className:t,style:Ve({position:"relative"},a||{}),ref:O},F&&o.createElement(l.J9,{contrastLimits:Z,colors:C,channelsVisible:x,loader:I,selections:E,height:w.height,width:w.width,extensions:M?[Be]:[Te],colormap:M||"viridis",onViewportLoad:j,viewStates:N,overviewOn:!!m,overview:m,lensSelection:R&&A?V:void 0,lensEnabled:R&&A})))}Ne.propTypes={className:u().string,onStateChange:u().func,onRegisterStateActions:u().func,onViewerStateChanged:u().func,style:u().object,minZoomBackOff:u().number,maxZoomBackOff:u().number,defaultZoomBackOff:u().number,overview:u().object},Ne.defaultProps={className:void 0,onStateChange:void 0,onRegisterStateActions:void 0,onViewerStateChanged:void 0,style:void 0,minZoomBackOff:0,maxZoomBackOff:void 0,defaultZoomBackOff:0,overview:void 0};var Ue=Ne;function Fe(e,t){var r=arguments.length>2&&void 0!==arguments[2]?arguments[2]:{},a=r.onStateChange,c=r.onRegisterStateActions,s=r.onViewerStateChanged;i.render(o.createElement(Ue,(0,n.Z)({onRegisterStateActions:c,onStateChange:a,onViewerStateChanged:s},t)),e)}},802:function(){},2195:function(){},1998:function(){},9521:function(){},9214:function(){},3752:function(){},3640:function(){},2630:function(){}}]);