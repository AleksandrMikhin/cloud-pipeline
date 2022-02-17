!function(){"use strict";var e,t,n={4477:function(e,t){t.Z=["z","t"]},5671:function(e,t,n){function i(e,t){if(!(e instanceof t))throw new TypeError("Cannot call a class as a function")}n.d(t,{Z:function(){return i}})},3144:function(e,t,n){function i(e,t){for(var n=0;n<t.length;n++){var i=t[n];i.enumerable=i.enumerable||!1,i.configurable=!0,"value"in i&&(i.writable=!0),Object.defineProperty(e,i.key,i)}}function r(e,t,n){return t&&i(e.prototype,t),n&&i(e,n),Object.defineProperty(e,"prototype",{writable:!1}),e}n.d(t,{Z:function(){return r}})},4942:function(e,t,n){function i(e,t,n){return t in e?Object.defineProperty(e,t,{value:n,enumerable:!0,configurable:!0,writable:!0}):e[t]=n,e}n.d(t,{Z:function(){return i}})}},i={};function r(e){var t=i[e];if(void 0!==t)return t.exports;var o=i[e]={exports:{}};return n[e](o,o.exports,r),o.exports}r.m=n,r.n=function(e){var t=e&&e.__esModule?function(){return e.default}:function(){return e};return r.d(t,{a:t}),t},r.d=function(e,t){for(var n in t)r.o(t,n)&&!r.o(e,n)&&Object.defineProperty(e,n,{enumerable:!0,get:t[n]})},r.f={},r.e=function(e){return Promise.all(Object.keys(r.f).reduce((function(t,n){return r.f[n](e,t),t}),[]))},r.u=function(e){return(822===e?"hcs-image-inject":e)+".js"},r.g=function(){if("object"==typeof globalThis)return globalThis;try{return this||new Function("return this")()}catch(e){if("object"==typeof window)return window}}(),r.o=function(e,t){return Object.prototype.hasOwnProperty.call(e,t)},e={},t="HcsImageViewer:",r.l=function(n,i,o,a){if(e[n])e[n].push(i);else{var c,u;if(void 0!==o)for(var s=document.getElementsByTagName("script"),l=0;l<s.length;l++){var f=s[l];if(f.getAttribute("src")==n||f.getAttribute("data-webpack")==t+o){c=f;break}}c||(u=!0,(c=document.createElement("script")).charset="utf-8",c.timeout=120,r.nc&&c.setAttribute("nonce",r.nc),c.setAttribute("data-webpack",t+o),c.src=n),e[n]=[i];var h=function(t,i){c.onerror=c.onload=null,clearTimeout(v);var r=e[n];if(delete e[n],c.parentNode&&c.parentNode.removeChild(c),r&&r.forEach((function(e){return e(i)})),t)return t(i)},v=setTimeout(h.bind(null,void 0,{type:"timeout",target:c}),12e4);c.onerror=h.bind(null,c.onerror),c.onload=h.bind(null,c.onload),u&&document.head.appendChild(c)}},r.r=function(e){"undefined"!=typeof Symbol&&Symbol.toStringTag&&Object.defineProperty(e,Symbol.toStringTag,{value:"Module"}),Object.defineProperty(e,"__esModule",{value:!0})},function(){var e;r.g.importScripts&&(e=r.g.location+"");var t=r.g.document;if(!e&&t&&(t.currentScript&&(e=t.currentScript.src),!e)){var n=t.getElementsByTagName("script");n.length&&(e=n[n.length-1].src)}if(!e)throw new Error("Automatic publicPath is not supported in this browser");e=e.replace(/#.*$/,"").replace(/\?.*$/,"").replace(/\/[^\/]+$/,"/"),r.p=e}(),function(){var e={47:0};r.f.j=function(t,n){var i=r.o(e,t)?e[t]:void 0;if(0!==i)if(i)n.push(i[2]);else{var o=new Promise((function(n,r){i=e[t]=[n,r]}));n.push(i[2]=o);var a=r.p+r.u(t),c=new Error;r.l(a,(function(n){if(r.o(e,t)&&(0!==(i=e[t])&&(e[t]=void 0),i)){var o=n&&("load"===n.type?"missing":n.type),a=n&&n.target&&n.target.src;c.message="Loading chunk "+t+" failed.\n("+o+": "+a+")",c.name="ChunkLoadError",c.type=o,c.request=a,i[1](c)}}),"chunk-"+t,t)}};var t=function(t,n){var i,o,a=n[0],c=n[1],u=n[2],s=0;if(a.some((function(t){return 0!==e[t]}))){for(i in c)r.o(c,i)&&(r.m[i]=c[i]);u&&u(r)}for(t&&t(n);s<a.length;s++)o=a[s],r.o(e,o)&&e[o]&&e[o][0](),e[o]=0},n=self.webpackChunkHcsImageViewer=self.webpackChunkHcsImageViewer||[];n.forEach(t.bind(null,0)),n.push=t.bind(null,n.push.bind(n))}();var o={};!function(){r.r(o),r.d(o,{Viewer:function(){return l},constants:function(){return e}});var e={};r.r(e),r.d(e,{ColorMapProfiles:function(){return f},GlobalDimensionFields:function(){return h.Z}});var t=r(5671),n=r(3144),i=r(4942),a=Symbol("log message"),c=Symbol("log error"),u=Symbol("callbacks"),s=function(){function e(){var n=this,o=arguments.length>0&&void 0!==arguments[0]?arguments[0]:{};(0,t.Z)(this,e),(0,i.Z)(this,"Events",{stateChanged:"state-changed",viewerStateChanged:"viewer-state-changed"}),(0,i.Z)(this,"initializationPromise",void 0),(0,i.Z)(this,"verbose",1),(0,i.Z)(this,a,(function(){for(var e,t=arguments.length,i=new Array(t),r=0;r<t;r++)i[r]=arguments[r];return 2===n.verbose?(e=console).log.apply(e,["[HCS Image Viewer]"].concat(i)):void 0})),(0,i.Z)(this,c,(function(){for(var e,t=arguments.length,i=new Array(t),r=0;r<t;r++)i[r]=arguments[r];return 0!==n.verbose?(e=console).error.apply(e,["[HCS Image Viewer]"].concat(i)):void 0}));var s=o.container,l=o.className,f=o.style,h=o.verbose,v=void 0===h?1:h,d=o.minZoomBackOff,m=o.maxZoomBackOff,p=o.defaultZoomBackOff,g=o.overview;this.verbose="boolean"==typeof v?v?2:0:v,this.listeners=[],this.initializationPromise=new Promise((function(e,t){Promise.all([r.e(256),r.e(822)]).then(r.bind(r,2980)).then((function(t){(0,t.default)(s,{className:l,style:f,minZoomBackOff:d,maxZoomBackOff:m,defaultZoomBackOff:p,overview:g},{onStateChange:function(e){n.state=e,n.emit(n.Events.stateChanged,e)},onRegisterStateActions:function(t){n[u]=t,e(n)},onViewerStateChanged:function(e){n.viewerState=e,n.emit(n.Events.viewerStateChanged,e)}})})).catch(t)})),this.initializationPromise.then((function(){return n[a]("initialized")})).catch((function(e){return n[c]("initialization error: ".concat(e.message))}))}return(0,n.Z)(e,[{key:"addEventListener",value:function(e,t){this.listeners.push({event:e,listener:t})}},{key:"removeEventListener",value:function(e,t){var n=this.listeners.findIndex((function(n){return n.event===e&&n.listener===t}));n>=0&&this.listeners.splice(n,1)}},{key:"emit",value:function(e,t){var n=this;this.listeners.filter((function(t){return t.event===e&&"function"==typeof t.listener})).map((function(e){return e.listener})).forEach((function(e){return e(n,t)}))}},{key:"onInitialized",value:function(e){this.initializationPromise.then(e).catch((function(){}))}},{key:"waitForInitialization",value:function(){var e=this;return new Promise((function(t,n){e.initializationPromise.then((function(){return t()})).catch(n)}))}},{key:"getCallback",value:function(e){return this[u]&&"function"==typeof this[u][e]?this[u][e]:function(){}}},{key:"setData",value:function(e,t){var n=this;return new Promise((function(i,r){n.waitForInitialization().then((function(){n.state&&n.state.url===e&&n.state.offsetsUrl===t?i(n):n.getCallback("setData")(e,t,(function(e){e&&e.error?r(new Error(e.error)):i(n)}))})).catch(r)}))}},{key:"setImage",value:function(e){var t=this;return new Promise((function(n,i){t.waitForInitialization().then((function(){t.getCallback("setImage")(e,(function(e){e&&e.error?i(new Error(e.error)):n(t)}))})).catch(i)}))}},{key:"setChannelProperties",value:function(e,t){var n=this;return new Promise((function(i,r){n.waitForInitialization().then((function(){n.getCallback("setChannelProperties")(e,t),i()})).catch(r)}))}},{key:"setColorMap",value:function(e){var t=this;return new Promise((function(n,i){t.waitForInitialization().then((function(){t.getCallback("setColorMap")(e),n()})).catch(i)}))}},{key:"setLensChannel",value:function(e){var t=this;return new Promise((function(n,i){t.waitForInitialization().then((function(){t.getCallback("setLensChannel")(e),n()})).catch(i)}))}},{key:"setLensEnabled",value:function(e){var t=this;return new Promise((function(n,i){t.waitForInitialization().then((function(){t.getCallback("setLensEnabled")(e),n()})).catch(i)}))}}]),e}(),l=s,f=["viridis","greys","magma","jet","hot","bone","copper","summer","density","inferno"],h=r(4477)}(),window.HcsImageViewer=o}();