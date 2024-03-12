(function(){'use strict';function ca(a){var b=0;return function(){return b<a.length?{done:!1,value:a[b++]}:{done:!0}}}var da="function"==typeof Object.defineProperties?Object.defineProperty:function(a,b,c){if(a==Array.prototype||a==Object.prototype)return a;a[b]=c.value;return a};
function ea(a){a=["object"==typeof globalThis&&globalThis,a,"object"==typeof window&&window,"object"==typeof self&&self,"object"==typeof global&&global];for(var b=0;b<a.length;++b){var c=a[b];if(c&&c.Math==Math)return c}throw Error("Cannot find global object");}var fa=ea(this);function q(a,b){if(b)a:{var c=fa;a=a.split(".");for(var d=0;d<a.length-1;d++){var e=a[d];if(!(e in c))break a;c=c[e]}a=a[a.length-1];d=c[a];b=b(d);b!=d&&null!=b&&da(c,a,{configurable:!0,writable:!0,value:b})}}
q("Symbol",function(a){function b(f){if(this instanceof b)throw new TypeError("Symbol is not a constructor");return new c(d+(f||"")+"_"+e++,f)}function c(f,g){this.g=f;da(this,"description",{configurable:!0,writable:!0,value:g})}if(a)return a;c.prototype.toString=function(){return this.g};var d="jscomp_symbol_"+(1E9*Math.random()>>>0)+"_",e=0;return b});
function r(a){var b="undefined"!=typeof Symbol&&Symbol.iterator&&a[Symbol.iterator];if(b)return b.call(a);if("number"==typeof a.length)return{next:ca(a)};throw Error(String(a)+" is not an iterable or ArrayLike");}var ha="function"==typeof Object.create?Object.create:function(a){function b(){}b.prototype=a;return new b},ia;
if("function"==typeof Object.setPrototypeOf)ia=Object.setPrototypeOf;else{var ja;a:{var ka={a:!0},la={};try{la.__proto__=ka;ja=la.a;break a}catch(a){}ja=!1}ia=ja?function(a,b){a.__proto__=b;if(a.__proto__!==b)throw new TypeError(a+" is not extensible");return a}:null}var ma=ia;
function na(a,b){a.prototype=ha(b.prototype);a.prototype.constructor=a;if(ma)ma(a,b);else for(var c in b)if("prototype"!=c)if(Object.defineProperties){var d=Object.getOwnPropertyDescriptor(b,c);d&&Object.defineProperty(a,c,d)}else a[c]=b[c];a.H=b.prototype}q("Number.isFinite",function(a){return a?a:function(b){return"number"!==typeof b?!1:!isNaN(b)&&Infinity!==b&&-Infinity!==b}});q("Object.is",function(a){return a?a:function(b,c){return b===c?0!==b||1/b===1/c:b!==b&&c!==c}});
q("Array.prototype.includes",function(a){return a?a:function(b,c){var d=this;d instanceof String&&(d=String(d));var e=d.length;c=c||0;for(0>c&&(c=Math.max(c+e,0));c<e;c++){var f=d[c];if(f===b||Object.is(f,b))return!0}return!1}});
q("String.prototype.includes",function(a){return a?a:function(b,c){if(null==this)throw new TypeError("The 'this' value for String.prototype.includes must not be null or undefined");if(b instanceof RegExp)throw new TypeError("First argument to String.prototype.includes must not be a regular expression");return-1!==this.indexOf(b,c||0)}});q("Number.isNaN",function(a){return a?a:function(b){return"number"===typeof b&&isNaN(b)}});/*

 Copyright The Closure Library Authors.
 SPDX-License-Identifier: Apache-2.0
*/
var t=this||self;function oa(a){a:{var b=["CLOSURE_FLAGS"];for(var c=t,d=0;d<b.length;d++)if(c=c[b[d]],null==c){b=null;break a}b=c}a=b&&b[a];return null!=a?a:!1};var pa=Array.prototype.indexOf?function(a,b){return Array.prototype.indexOf.call(a,b,void 0)}:function(a,b){if("string"===typeof a)return"string"!==typeof b||1!=b.length?-1:a.indexOf(b,0);for(var c=0;c<a.length;c++)if(c in a&&a[c]===b)return c;return-1};var qa=oa(610401301),ra=oa(188588736);var u,sa=t.navigator;u=sa?sa.userAgentData||null:null;function ta(a){return qa?u?u.brands.some(function(b){return(b=b.brand)&&-1!=b.indexOf(a)}):!1:!1}function x(a){var b;a:{if(b=t.navigator)if(b=b.userAgent)break a;b=""}return-1!=b.indexOf(a)};function y(){return qa?!!u&&0<u.brands.length:!1}function xa(){return y()?ta("Chromium"):(x("Chrome")||x("CriOS"))&&!(y()?0:x("Edge"))||x("Silk")};var ya=y()?!1:x("Trident")||x("MSIE");function za(a){a=void 0===a?document:a;return a.createElement("img")};function Aa(a,b,c){var d=!1;d=void 0===d?!1:d;a.google_image_requests||(a.google_image_requests=[]);var e=za(a.document);if(c){var f=function(){if(c){var g=a.google_image_requests,h=pa(g,e);0<=h&&Array.prototype.splice.call(g,h,1)}e.removeEventListener&&e.removeEventListener("load",f,!1);e.removeEventListener&&e.removeEventListener("error",f,!1)};e.addEventListener&&e.addEventListener("load",f,!1);e.addEventListener&&e.addEventListener("error",f,!1)}d&&(e.attributionSrc="");e.src=b;a.google_image_requests.push(e)}
;!x("Android")||xa();xa();x("Safari")&&(xa()||(y()?0:x("Coast"))||(y()?0:x("Opera"))||(y()?0:x("Edge"))||(y()?ta("Microsoft Edge"):x("Edg/"))||y()&&ta("Opera"));var Ba={},z=null;
function Ca(a){var b;void 0===b&&(b=0);if(!z){z={};for(var c="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".split(""),d=["+/=","+/","-_=","-_.","-_"],e=0;5>e;e++){var f=c.concat(d[e].split(""));Ba[e]=f;for(var g=0;g<f.length;g++){var h=f[g];void 0===z[h]&&(z[h]=g)}}}b=Ba[b];c=Array(Math.floor(a.length/3));d=b[64]||"";for(e=f=0;f<a.length-2;f+=3){var l=a[f],n=a[f+1];h=a[f+2];g=b[l>>2];l=b[(l&3)<<4|n>>4];n=b[(n&15)<<2|h>>6];h=b[h&63];c[e++]=g+l+n+h}g=0;h=d;switch(a.length-f){case 2:g=
a[f+1],h=b[(g&15)<<2]||d;case 1:a=a[f],c[e]=b[a>>2]+b[(a&3)<<4|g>>4]+h+d}return c.join("")};var Da,Ea="function"===typeof String.prototype.B,Fa="undefined"!==typeof TextEncoder;var Ga="undefined"!==typeof Uint8Array,Ha=!ya&&"function"===typeof btoa;var Ia=0,Ja=0,Ka;function La(){this.g=[]}La.prototype.length=function(){return this.g.length};La.prototype.end=function(){var a=this.g;this.g=[];return a};function A(a,b){for(;127<b;)a.g.push(b&127|128),b>>>=7;a.g.push(b)}function Ma(a,b){if(0<=b)A(a,b);else{for(var c=0;9>c;c++)a.g.push(b&127|128),b>>=7;a.g.push(1)}}function Na(a,b){a.g.push(b>>>0&255);a.g.push(b>>>8&255);a.g.push(b>>>16&255);a.g.push(b>>>24&255)};function Oa(){this.j=[];this.i=0;this.g=new La}function B(a,b){0!==b.length&&(a.j.push(b),a.i+=b.length)};function C(a,b){this.g=a;this.v=b};function D(a){return Array.prototype.slice.call(a)};var F;F="function"===typeof Symbol&&"symbol"===typeof Symbol()?Symbol():void 0;var Pa=F?function(a,b){a[F]|=b}:function(a,b){void 0!==a.g?a.g|=b:Object.defineProperties(a,{g:{value:b,configurable:!0,writable:!0,enumerable:!1}})},Qa=F?function(a,b){a[F]&=~b}:function(a,b){void 0!==a.g&&(a.g&=~b)};function G(a,b,c){return c?a|b:a&~b}
var H=F?function(a){return a[F]|0}:function(a){return a.g|0},I=F?function(a){return a[F]}:function(a){return a.g},J=F?function(a,b){a[F]=b;return a}:function(a,b){void 0!==a.g?a.g=b:Object.defineProperties(a,{g:{value:b,configurable:!0,writable:!0,enumerable:!1}});return a};function Ra(a,b){J(b,(a|0)&-14591)}function Sa(a,b){J(b,(a|34)&-14557)}function Ta(a){a=a>>14&1023;return 0===a?536870912:a};var K={},Ua={};function Va(a){return!(!a||"object"!==typeof a||a.g!==Ua)}function Wa(a){return null!==a&&"object"===typeof a&&!Array.isArray(a)&&a.constructor===Object}function L(a,b,c){if(!Array.isArray(a)||a.length)return!1;var d=H(a);if(d&1)return!0;if(!(b&&(Array.isArray(b)?b.includes(c):b.has(c))))return!1;J(a,d|1);return!0}var Xa,Ya=[];J(Ya,55);Xa=Object.freeze(Ya);function M(a){if(a&2)throw Error();}Object.freeze(new function(){});Object.freeze(new function(){});function Za(a){a=Error(a);a.__closure__error__context__984382||(a.__closure__error__context__984382={});a.__closure__error__context__984382.severity="warning";return a};function $a(a){if(!Number.isFinite(a))throw Za("enum");return a|0}function ab(a){if("number"!==typeof a)throw Za("int32");if(!Number.isFinite(a))throw Za("int32");return a|0}function bb(a){if(null==a)return a;if("string"===typeof a){if(!a)return;a=+a}if("number"===typeof a)return Number.isFinite(a)?a|0:void 0}function N(a){if(null!=a&&"string"!==typeof a)throw Error();return a};var P,cb,db;function eb(a){switch(typeof a){case "boolean":return cb||(cb=[0,void 0,!0]);case "number":return 0<a?void 0:0===a?db||(db=[0,void 0]):[-a,void 0];case "string":return[0,a];case "object":return a}}
function Q(a,b,c){null==a&&(a=P);P=void 0;if(null==a){var d=96;c?(a=[c],d|=512):a=[];b&&(d=d&-16760833|(b&1023)<<14)}else{if(!Array.isArray(a))throw Error();d=H(a);if(d&64)return a;d|=64;if(c&&(d|=512,c!==a[0]))throw Error();a:{c=a;var e=c.length;if(e){var f=e-1;if(Wa(c[f])){d|=256;b=f-(+!!(d&512)-1);if(1024<=b)throw Error();d=d&-16760833|(b&1023)<<14;break a}}if(b){b=Math.max(b,e-(+!!(d&512)-1));if(1024<b)throw Error();d=d&-16760833|(b&1023)<<14}}}J(a,d);return a};function gb(a){switch(typeof a){case "number":return isFinite(a)?a:String(a);case "boolean":return a?1:0;case "object":if(a)if(Array.isArray(a)){if(L(a,void 0,0))return}else if(Ga&&null!=a&&a instanceof Uint8Array){if(Ha){for(var b="",c=0,d=a.length-10240;c<d;)b+=String.fromCharCode.apply(null,a.subarray(c,c+=10240));b+=String.fromCharCode.apply(null,c?a.subarray(c):a);a=btoa(b)}else a=Ca(a);return a}}return a};function hb(a,b,c){a=D(a);var d=a.length,e=b&256?a[d-1]:void 0;d+=e?-1:0;for(b=b&512?1:0;b<d;b++)a[b]=c(a[b]);if(e){b=a[b]={};for(var f in e)b[f]=c(e[f])}return a}function ib(a,b,c,d,e){if(null!=a){if(Array.isArray(a))a=L(a,void 0,0)?void 0:e&&H(a)&2?a:jb(a,b,c,void 0!==d,e);else if(Wa(a)){var f={},g;for(g in a)f[g]=ib(a[g],b,c,d,e);a=f}else a=b(a,d);return a}}function jb(a,b,c,d,e){var f=d||c?H(a):0;d=d?!!(f&32):void 0;a=D(a);for(var g=0;g<a.length;g++)a[g]=ib(a[g],b,c,d,e);c&&c(f,a);return a}
function kb(a){return a.l===K?a.toJSON():gb(a)};function lb(a,b,c){c=void 0===c?Sa:c;if(null!=a){if(Ga&&a instanceof Uint8Array)return b?a:new Uint8Array(a);if(Array.isArray(a)){var d=H(a);if(d&2)return a;b&&(b=0===d||!!(d&32)&&!(d&64||!(d&16)));return b?J(a,(d|34)&-12293):jb(a,lb,d&4?Sa:c,!0,!0)}a.l===K&&(c=a.h,d=I(c),a=d&2?a:mb(a,c,d,!0));return a}}function mb(a,b,c,d){a=a.constructor;P=b=nb(b,c,d);b=new a(b);P=void 0;return b}function nb(a,b,c){var d=c||b&2?Sa:Ra,e=!!(b&32);a=hb(a,b,function(f){return lb(f,e,d)});Pa(a,32|(c?2:0));return a};function ob(a,b,c,d){if(-1===c)return null;if(c>=Ta(b)){if(b&256)return a[a.length-1][c]}else{var e=a.length;if(d&&b&256&&(d=a[e-1][c],null!=d))return d;b=c+(+!!(b&512)-1);if(b<e)return a[b]}}function R(a,b,c){a=a.h;var d=I(a);M(d);S(a,d,b,c)}
function S(a,b,c,d,e){var f=Ta(b);if(c>=f||e){var g=b;if(b&256)e=a[a.length-1];else{if(null==d)return g;e=a[f+(+!!(b&512)-1)]={};g|=256}e[c]=d;c<f&&(a[c+(+!!(b&512)-1)]=void 0);g!==b&&J(a,g);return g}a[c+(+!!(b&512)-1)]=d;b&256&&(a=a[a.length-1],c in a&&delete a[c]);return b}function pb(a){return!!(2&a)&&!!(4&a)||!!(2048&a)}
function T(a,b,c,d){a=a.h;var e=I(a);M(e);for(var f=e,g=0,h=0;h<c.length;h++){var l=c[h];null!=ob(a,f,l)&&(0!==g&&(f=S(a,f,g)),g=l)}(c=g)&&c!==b&&null!=d&&(e=S(a,e,c));S(a,e,b,d)}
function qb(a,b,c,d,e,f,g){var h=!!(2&b),l=h?1:2,n=1===l;l=2===l;f=!!f;g&&(g=!h);h=ob(a,b,d,e);h=Array.isArray(h)?h:Xa;var k=H(h),p=!!(4&k);if(!p){var m=k;0===m&&(m=U(m,b,f));m=G(m,1,!0);k=h;var v=b,E;(E=!!(2&m))&&(v=G(v,2,!0));for(var ua=!E,va=!0,aa=0,wa=0;aa<k.length;aa++){var w=k[aa];var ba=c;if(null==w||"object"!==typeof w||w.l!==K)if(Array.isArray(w)){var fb=H(w),O=fb;0===O&&(O|=v&32);O|=v&2;O!==fb&&J(w,O);w=new ba(w)}else w=void 0;w instanceof c&&(E||(ba=!!(H(w.h)&2),ua&&(ua=!ba),va&&(va=ba)),
k[wa++]=w)}wa<aa&&(k.length=wa);m=G(m,4,!0);m=G(m,16,va);m=G(m,8,ua);J(k,m);E&&Object.freeze(k);k=m}c=!!(8&k)||n&&!h.length;if(g&&!c){pb(k)&&(h=D(h),k=U(k,b,f),b=S(a,b,d,h,e));g=h;c=k;for(k=0;k<g.length;k++)m=g[k],v=m.h,E=I(v),v=E&2?mb(m,v,E,!1):m,m!==v&&(g[k]=v);c=G(c,8,!0);c=G(c,16,!g.length);J(g,c);k=c}pb(k)||(g=k,n?k=G(k,!h.length||16&k&&(!p||32&k)?2:2048,!0):f||(k=G(k,32,!1)),k!==g&&J(h,k),n&&Object.freeze(h));l&&pb(k)&&(h=D(h),k=U(k,b,f),J(h,k),S(a,b,d,h,e));return h}
function rb(a,b){a=a.h;var c=I(a);return qb(a,c,sb,b,void 0,!1,!(2&c))}function tb(a,b,c){var d=a.h,e=I(d);M(e);if(null==c)return S(d,e,b),a;for(var f=H(c),g=f,h=!!(2&f)||!!(2048&f),l=h||Object.isFrozen(c),n=!0,k=!0,p=0;p<c.length;p++){var m=c[p];h||(m=!!(H(m.h)&2),n&&(n=!m),k&&(k=m))}h||(f=G(f,5,!0),f=G(f,8,n),f=G(f,16,k));l&&f!==g&&(c=D(c),g=0,f=U(f,e,!0));f!==g&&J(c,f);S(d,e,b,c);return a}function U(a,b,c){a=G(a,2,!!(2&b));a=G(a,32,!!(32&b)&&c);return a=G(a,2048,!1)};function V(a,b,c){this.h=Q(a,b,c)}V.prototype.toJSON=function(){return ub(this,jb(this.h,kb,void 0,void 0,!1),!0)};V.prototype.l=K;V.prototype.toString=function(){return ub(this,this.h,!1).toString()};
function ub(a,b,c){var d=ra?void 0:a.constructor.u;var e=I(c?a.h:b);a=b.length;if(!a)return b;var f;if(Wa(c=b[a-1])){a:{var g=c;var h={},l=!1,n;for(n in g){var k=g[n];if(Array.isArray(k)){var p=k;if(L(k,d,+n)||Va(k)&&0===k.size)k=null;k!=p&&(l=!0)}null!=k?h[n]=k:l=!0}if(l){for(var m in h){g=h;break a}g=null}}g!=c&&(f=!0);a--}for(n=+!!(e&512)-1;0<a;a--){m=a-1;c=b[m];m-=n;if(!(null==c||L(c,d,m)||Va(c)&&0===c.size))break;var v=!0}if(!f&&!v)return b;b=Array.prototype.slice.call(b,0,a);g&&b.push(g);return b}
;var vb=Symbol();function wb(a,b,c){a[b]=c}var xb=Symbol();function yb(a){var b=a[xb];if(!b){var c=zb(a);b=function(d,e){return Ab(d,e,c)};a[xb]=b}return b}var Bb=Symbol();function Cb(a){return a.g}function Db(a,b){var c,d,e=a.g;return function(f,g,h){return e(f,g,h,d||(d=zb(b).g),c||(c=yb(b)))}}
function zb(a){var b=a[Bb];if(b)return b;b=a[Bb]={};var c=Cb,d=Db;var e=void 0===e?wb:e;b.g=eb(a[0]);var f=0,g=a[++f];g&&g.constructor===Object&&(b.A=g,g=a[++f],"function"===typeof g&&(b.j=g,b.i=a[++f],g=a[++f]));for(var h={};Array.isArray(g)&&"number"===typeof g[0]&&0<g[0];){for(var l=0;l<g.length;l++)h[g[l]]=g;g=a[++f]}for(l=1;void 0!==g;){"number"===typeof g&&(l+=g,g=a[++f]);var n=void 0;if(g instanceof C)var k=g;else k=Eb,f--;if(k.v){g=a[++f];n=a;var p=f;"function"==typeof g&&(g=g(),n[p]=g);n=
g}g=a[++f];p=l+1;"number"===typeof g&&0>g&&(p-=g,g=a[++f]);for(;l<p;l++){var m=h[l];e(b,l,n?d(k,n,m):c(k,m))}}Fb in a&&vb in a&&Bb in a&&(a.length=0);return b}var Fb=Symbol();function Gb(a,b){var c=a[b];if(c)return c;if(c=a.A)if(c=c[b]){c=Array.isArray(c)?c[0]instanceof C?c:[Hb,c]:[c,void 0];var d=c[0].g;if(c=c[1]){var e=yb(c),f=zb(c).g;c=(c=a.i)?c(f,e):function(g,h,l){return d(g,h,l,f,e)}}else c=d;return a[b]=c}}
function Ab(a,b,c){for(var d=I(a),e=+!!(d&512)-1,f=a.length,g=f+(d&256?-1:0),h=d&512?1:0;h<g;h++){var l=a[h];if(null!=l){var n=h-e,k=Gb(c,n);k&&k(b,l,n)}}if(d&256){a=a[f-1];for(var p in a)d=+p,Number.isNaN(d)||(e=a[p],null!=e&&(f=Gb(c,d))&&f(b,e,d))}}
function Ib(a,b,c){b=null==b||"string"===typeof b?b:void 0;if(null!=b){var d=!1;d=void 0===d?!1:d;if(Fa){if(d&&(Ea?!b.B():/(?:[^\uD800-\uDBFF]|^)[\uDC00-\uDFFF]|[\uD800-\uDBFF](?![\uDC00-\uDFFF])/.test(b)))throw Error("Found an unpaired surrogate");b=(Da||(Da=new TextEncoder)).encode(b)}else{for(var e=0,f=new Uint8Array(3*b.length),g=0;g<b.length;g++){var h=b.charCodeAt(g);if(128>h)f[e++]=h;else{if(2048>h)f[e++]=h>>6|192;else{if(55296<=h&&57343>=h){if(56319>=h&&g<b.length){var l=b.charCodeAt(++g);
if(56320<=l&&57343>=l){h=1024*(h-55296)+l-56320+65536;f[e++]=h>>18|240;f[e++]=h>>12&63|128;f[e++]=h>>6&63|128;f[e++]=h&63|128;continue}else g--}if(d)throw Error("Found an unpaired surrogate");h=65533}f[e++]=h>>12|224;f[e++]=h>>6&63|128}f[e++]=h&63|128}}b=e===f.length?f:f.subarray(0,e)}A(a.g,8*c+2);A(a.g,b.length);B(a,a.g.end());B(a,b)}}
function Jb(a,b,c,d,e){b=b instanceof V?b.h:Array.isArray(b)?Q(b,d[0],d[1]):void 0;if(null!=b){A(a.g,8*c+2);c=a.g.end();B(a,c);c.push(a.i);e(b,a);e=c.pop();for(e=a.i+a.g.length()-e;127<e;)c.push(e&127|128),e>>>=7,a.i++;c.push(e);a.i++}}
var Kb=new C(function(a,b,c){b=null==b||"number"===typeof b?b:"NaN"===b||"Infinity"===b||"-Infinity"===b?Number(b):void 0;null!=b&&(A(a.g,8*c+1),a=a.g,c=Ka||(Ka=new DataView(new ArrayBuffer(8))),c.setFloat64(0,+b,!0),Ia=c.getUint32(0,!0),Ja=c.getUint32(4,!0),Na(a,Ia),Na(a,Ja))},!1),Lb=new C(function(a,b,c){b=bb(b);null!=b&&null!=b&&(A(a.g,8*c),Ma(a.g,b))},!1),Mb=new C(Ib,!1),Nb=new C(Ib,!1),Hb=new C(Jb,!0),Eb=new C(Jb,!0),Ob;
Ob=new C(function(a,b,c,d,e){if(Array.isArray(b))for(var f=0;f<b.length;f++)Jb(a,b[f],c,d,e)},!0);var Pb=new C(function(a,b,c){b=bb(b);null!=b&&(b=parseInt(b,10),A(a.g,8*c),Ma(a.g,b))},!1);function sb(a){this.h=Q(a)}na(sb,V);var Qb=[1,2,3],Rb=[4,5],Sb=[0,Qb,Rb,Pb,-1,Nb,Kb,Nb,Lb];function Tb(a){this.h=Q(a)}na(Tb,V);Tb.u=[1];Tb.prototype.g=function(a){return function(){var b=new Oa;Ab(this.h,b,zb(a));B(b,b.g.end());for(var c=new Uint8Array(b.i),d=b.j,e=d.length,f=0,g=0;g<e;g++){var h=d[g];c.set(h,f);f+=h.length}b.j=[c];return c}}([0,Ob,Sb,Mb,1,Mb,Lb]);function Ub(a){this.h=Q(a)}na(Ub,V);Ub.prototype.setData=function(a,b){var c=sb,d=this.h,e=I(d);M(e);d=qb(d,e,c,2,!1,!0);b=null!=b?b:new c;if("number"!==typeof a||0>a||a>d.length)throw Error();void 0!=a?d.splice(a,1,b):d.push(b);H(b.h)&2?Qa(d,8):Qa(d,16);return this};Ub.u=[1,2];function Vb(a){this.i=a;this.data=[];this.g=[]}Vb.prototype.setData=function(a,b,c){this.i.includes(c)&&this.data.push({key:a,value:b,channel:c})};function Wb(a){return a.data.some(function(b){return 1===b.channel})}Vb.prototype.setAttribute=function(a,b){this.g.push({key:a,value:b})};
function Xb(a,b,c,d){var e=new sb;"string"===typeof a?T(e,3,Qb,N(a)):d?T(e,1,Qb,null==a?a:$a(a)):T(e,2,Qb,null==a?a:$a(a));if("number"===typeof b){if(null==b)a=b;else{if("number"!==typeof b)throw Error("Value of float/double field must be a number, found "+typeof b+": "+b);a=b}T(e,4,Rb,a)}else T(e,5,Rb,N(b));c&&R(e,6,null==c?c:ab(c));return e};function W(){this.g=new Vb([]);this.D=Date.now();this.i=[];this.s=this.m=!1;this.o=100}
W.prototype.init=function(a,b,c,d,e,f){var g=this;this.g=new Vb(b);this.G=a;this.C=e;this.F=c;if(d){b=a=NaN;d=r(d);for(c=d.next();!c.done;c=d.next())e=r(c.value),c=e.next().value,e=e.next().value,6===c?a=Number(e):5===c?b=Number(e):this.g.setAttribute(c,e);!isNaN(a)&&0<=a?this.o=a:isNaN(b)||(this.m=!0,setInterval(this.j.bind(this),b),setTimeout(function(){Yb(g,"timeout")},3E5),document.addEventListener("visibilitychange",function(){"hidden"===document.visibilityState&&Yb(g,"document_hidden")}),window.addEventListener("beforeunload",
function(){Yb(g,"beforeunload")}))}if(f){f=r(f);for(a=f.next();!a.done;a=f.next())d=r(a.value),a=d.next().value,b=d.next().value,d=d.next().value,this.setData(a,b,d);"complete"===document.readyState?this.send():window.addEventListener("load",function(){g.send()})}};W.prototype.getBaseTime=function(){return this.D};W.prototype.setData=function(a,b,c){this.g.setData(a,b,c);this.i[c]?this.i[c]++:this.i[c]=1};W.prototype.setAttribute=function(a,b){this.g.setAttribute(a,b)};
W.prototype.send=function(a){var b=this;if(!this.m){var c=Wb(this.g)?0:this.o;a=null!=a?a:c;0<a?setTimeout(function(){return void b.j()},a):this.j()}};
W.prototype.j=function(){if(0<this.g.data.length){var a=this.G,b=this.C,c=this.F,d=this.g,e=[];var f=r(d.g);for(var g=f.next();!g.done;g=f.next())g=g.value,e.push(Xb(g.key,g.value,void 0,!0));f=[];d=r(d.data);for(g=d.next();!g.done;g=d.next())g=g.value,f.push(Xb(g.key,g.value,g.channel,!1));d=new Ub;e=tb(d,1,e);f=tb(e,2,f);e=new Tb;f=rb(f,1).concat(rb(f,2));e=tb(e,1,f);a&&R(e,2,N(a));c&&R(e,4,N(c));b&&R(e,5,null==b?b:ab(b));a="https://pagead2.googlesyndication.com/pagead/gen_204?id=mys&d="+Ca(e.g()).replace(/\//g,
"_").replace(/\+/g,"-");b=window;var h=void 0===h?!1:h;if(c=b.navigator)c=b.navigator.userAgent,c=/Chrome/.test(c)&&!/Edge/.test(c)?!0:!1;c&&b.navigator.sendBeacon?b.navigator.sendBeacon(a):Aa(b,a,void 0===h?!1:h);this.g.data=[]}};function Yb(a,b){a.s||(a.g.setData(32,b,4),a.i.forEach(function(c,d){a.g.setData(31,c,d)}),a.j(),a.s=!0)}
if(!window.mys||!window.mys.pingback){var Zb=new W,X=["mys","pingback"],Y=t;X[0]in Y||"undefined"==typeof Y.execScript||Y.execScript("var "+X[0]);for(var Z;X.length&&(Z=X.shift());)X.length||void 0===Zb?Y[Z]&&Y[Z]!==Object.prototype[Z]?Y=Y[Z]:Y=Y[Z]={}:Y[Z]=Zb};}).call(this);
