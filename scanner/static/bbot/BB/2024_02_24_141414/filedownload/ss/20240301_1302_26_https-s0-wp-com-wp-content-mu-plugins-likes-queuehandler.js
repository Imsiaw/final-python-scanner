var jetpackLikesWidgetBatch=[];var jetpackLikesMasterReady=false;var jetpackLikesLookAhead=2e3;var jetpackCommentLikesLoadedWidgets=[];var jetpackLikesDocReadyPromise=new Promise(e=>{if(document.readyState!=="loading"){e()}else{window.addEventListener("DOMContentLoaded",()=>e())}});function JetpackLikesPostMessage(e,t){if(typeof e==="string"){try{e=JSON.parse(e)}catch(e){return}}if(t&&typeof t.postMessage==="function"){try{t.postMessage(JSON.stringify({type:"likesMessage",data:e}),"*")}catch(e){return}}}function JetpackLikesBatchHandler(){const e=[];document.querySelectorAll("div.jetpack-likes-widget-unloaded").forEach(t=>{if(jetpackLikesWidgetBatch.indexOf(t.id)>-1){return}if(!jetpackIsScrolledIntoView(t)){return}jetpackLikesWidgetBatch.push(t.id);var i=/like-(post|comment)-wrapper-(\d+)-(\d+)-(\w+)/,o=i.exec(t.id),s;if(!o||o.length!==5){return}s={blog_id:o[2],width:t.width};if("post"===o[1]){s.post_id=o[3]}else if("comment"===o[1]){s.comment_id=o[3]}s.obj_id=o[4];e.push(s)});if(e.length>0){JetpackLikesPostMessage({event:"initialBatch",requests:e},window.frames["likes-master"])}}function JetpackLikesMessageListener(e){let t=e&&e.data;if(typeof t==="string"){try{t=JSON.parse(t)}catch(e){return}}const i=t&&t.type;const o=t&&t.data;if(i!=="likesMessage"||typeof o.event==="undefined"){return}const s="https://widgets.wp.com";if(s!==e.origin){return}switch(o.event){case"masterReady":jetpackLikesDocReadyPromise.then(()=>{jetpackLikesMasterReady=true;const e={event:"injectStyles"};const t=document.querySelector(".sd-text-color");const i=document.querySelector(".sd-link-color");const o=t&&getComputedStyle(t)||{};const s=i&&getComputedStyle(i)||{};if(document.querySelectorAll("iframe.admin-bar-likes-widget").length>0){JetpackLikesPostMessage({event:"adminBarEnabled"},window.frames["likes-master"]);const t=document.querySelector("#wpadminbar .quicklinks li#wp-admin-bar-wpl-like > a");const i=document.querySelector("#wpadminbar");e.adminBarStyles={background:t&&getComputedStyle(t).background,isRtl:i&&getComputedStyle(i).direction==="rtl"}}if(document.body.classList.contains("jetpack-reblog-enabled")){JetpackLikesPostMessage({event:"reblogsEnabled"},window.frames["likes-master"])}e.textStyles={color:o["color"],fontFamily:o["font-family"],fontSize:o["font-size"],direction:o["direction"],fontWeight:o["font-weight"],fontStyle:o["font-style"],textDecoration:o["text-decoration"]};e.linkStyles={color:s["color"],fontFamily:s["font-family"],fontSize:s["font-size"],textDecoration:s["text-decoration"],fontWeight:s["font-weight"],fontStyle:s["font-style"]};JetpackLikesPostMessage(e,window.frames["likes-master"]);JetpackLikesBatchHandler()});break;case"showLikeWidget":{const e=document.querySelector(`#${o.id} .likes-widget-placeholder`);if(e){e.style.display="none"}break}case"showCommentLikeWidget":{const e=document.querySelector(`#${o.id} .likes-widget-placeholder`);if(e){e.style.display="none"}break}case"killCommentLikes":document.querySelectorAll(".jetpack-comment-likes-widget-wrapper").forEach(e=>e.remove());break;case"clickReblogFlair":if(wpcom_reblog&&typeof wpcom_reblog.toggle_reblog_box_flair==="function"){wpcom_reblog.toggle_reblog_box_flair(o.obj_id,o.post_id)}break;case"hideOtherGravatars":{hideLikersPopover();break}case"showOtherGravatars":{const e=document.querySelector("#likes-other-gravatars");if(!e){break}const t=e.querySelector("ul");e.style.display="none";t.innerHTML="";e.querySelectorAll(".likes-text span").forEach(e=>e.textContent=o.totalLikesLabel);(o.likers||[]).forEach(async(e,i)=>{if(e.profile_URL.substr(0,4)!=="http"){return}const s=document.createElement("li");t.append(s);s.innerHTML=`
				<a href="${encodeURI(e.profile_URL)}" rel="nofollow" target="_parent" class="wpl-liker">
					<img src="${encodeURI(e.avatar_URL)}"
						alt=""
						style="width: 28px; height: 28px;" />
					<span></span>
				</a>
				`;s.classList.add(e.css_class);s.querySelector("img").alt=o.avatarAltTitle.replace("%s",e.name);s.querySelector("span").innerText=e.name;if(i===o.likers.length-1){s.addEventListener("keydown",e=>{if(e.key==="Tab"&&!e.shiftKey){e.preventDefault();hideLikersPopover();JetpackLikesPostMessage({event:"focusLikesCount",parent:o.parent},window.frames["likes-master"])}})}});const i=function(){const t=getComputedStyle(e);const i=t.direction==="rtl";const s=document.querySelector(`*[name='${o.parent}']`);const a=s.getBoundingClientRect();const n=s.ownerDocument.defaultView;const r={top:a.top+n.pageYOffset,left:a.left+n.pageXOffset};e.style.display="none";let l=0;e.style.top=r.top+o.position.top-1+"px";if(i){const t=o&&o.likers?Math.min(o.likers.length,5):0;l=r.left+o.position.left+24*t+4;e.style.transform="translateX(-100%)"}else{l=r.left+o.position.left}e.style.left=l+"px";const c=o.width-20;const d=Math.floor(c/37);let k=Math.ceil(o.likers.length/d)*37+17+22;if(k>204){k=204}const p=n.innerWidth;e.style.left="-9999px";e.style.display="block";const f=e.offsetWidth;const m=l+f;if(m>p&&!i){l=a.left+a.width-f}else if(l-f<0&&i){e.style.transform="none";l=a.left}e.style.left=l+"px";e.setAttribute("aria-hidden","false")};i();e.focus();const s=function(e,t){var i;return function(){var o=this;var s=arguments;clearTimeout(i);i=setTimeout(function(){e.apply(o,s)},t)}};const a=s(i,100);e.__resizeHandler=a;window.addEventListener("resize",a)}}}window.addEventListener("message",JetpackLikesMessageListener);function hideLikersPopover(){const e=document.querySelector("#likes-other-gravatars");if(e){e.style.display="none";e.setAttribute("aria-hidden","true");const t=e.__resizeHandler;if(t){window.removeEventListener("resize",t);delete e.__resizeHandler}}}document.addEventListener("click",hideLikersPopover);function JetpackLikesWidgetQueueHandler(){var e;if(!jetpackLikesMasterReady){setTimeout(JetpackLikesWidgetQueueHandler,500);return}jetpackUnloadScrolledOutWidgets();var t=jetpackGetUnloadedWidgetsInView();if(t.length>0){JetpackLikesBatchHandler()}for(var i=0,o=t.length;i<=o-1;i++){e=t[i].id;if(!e){continue}jetpackLoadLikeWidgetIframe(e)}}function jetpackLoadLikeWidgetIframe(e){if(typeof e==="undefined"){return}const t=document.querySelector("#"+e);t.querySelectorAll("iframe").forEach(e=>e.remove());const i=t.querySelector(".likes-widget-placeholder");if(i&&i.classList.contains("post-likes-widget-placeholder")){const e=document.createElement("iframe");e.classList.add("post-likes-widget","jetpack-likes-widget");e.name=t.dataset.name;e.src=t.dataset.src;e.height="55px";e.width="100%";e.frameBorder="0";e.scrolling="no";e.title=t.dataset.title;i.after(e)}if(i.classList.contains("comment-likes-widget-placeholder")){const e=document.createElement("iframe");e.class="comment-likes-widget-frame jetpack-likes-widget-frame";e.name=t.dataset.name;e.src=t.dataset.src;e.height="18px";e.width="100%";e.frameBorder="0";e.scrolling="no";t.querySelector(".comment-like-feedback").after(e);jetpackCommentLikesLoadedWidgets.push(e)}t.classList.remove("jetpack-likes-widget-unloaded");t.classList.add("jetpack-likes-widget-loading");t.querySelector("iframe").addEventListener("load",e=>{JetpackLikesPostMessage({event:"loadLikeWidget",name:e.target.name,width:e.target.width},window.frames["likes-master"]);t.classList.remove("jetpack-likes-widget-loading");t.classList.add("jetpack-likes-widget-loaded")})}function jetpackGetUnloadedWidgetsInView(){const e=document.querySelectorAll("div.jetpack-likes-widget-unloaded");return[...e].filter(e=>jetpackIsScrolledIntoView(e))}function jetpackIsScrolledIntoView(e){const t=e.getBoundingClientRect().top;const i=e.getBoundingClientRect().bottom;return t+jetpackLikesLookAhead>=0&&i<=window.innerHeight+jetpackLikesLookAhead}function jetpackUnloadScrolledOutWidgets(){for(let e=jetpackCommentLikesLoadedWidgets.length-1;e>=0;e--){const t=jetpackCommentLikesLoadedWidgets[e];if(!jetpackIsScrolledIntoView(t)){const i=t&&t.parentElement&&t.parentElement.parentElement;i.classList.remove("jetpack-likes-widget-loaded");i.classList.remove("jetpack-likes-widget-loading");i.classList.add("jetpack-likes-widget-unloaded");i.querySelectorAll(".comment-likes-widget-placeholder").forEach(e=>e.style.display="block");jetpackCommentLikesLoadedWidgets.splice(e,1);t.remove()}}}var jetpackWidgetsDelayedExec=function(e,t){var i;return function(){clearTimeout(i);i=setTimeout(t,e)}};var jetpackOnScrollStopped=jetpackWidgetsDelayedExec(250,JetpackLikesWidgetQueueHandler);JetpackLikesWidgetQueueHandler();window.addEventListener("scroll",jetpackOnScrollStopped,true);