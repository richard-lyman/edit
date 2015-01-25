/*
Copyright (c) 2014, Richard B. Lyman
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:

1. Redistributions of source code must retain the above copyright
notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright
notice, this list of conditions and the following disclaimer in the
documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY
WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.
*/
$("#editor").hide();
var e = ace.edit("editor"); e.setTheme("ace/theme/chrome");
e.getSession().setMode("ace/mode/markdown"); e.getSession().setUseWrapMode(true); e.getSession().setWrapLimitRange(80,80);
e.setOption("scrollPastEnd", true); e.setOption("showFoldWidgets", false); e.setOption("useSoftTabs", false);
function save(){
	if(!$("#editor").is(":visible")){ return; };
	$.post(window.location.pathname, e.getValue()) .done(function(d){ $("#result").html(d); }) .fail(function(){ console.log("Failed"); });
}
function toggle(){ $("#editor").scope().toggle(); }
function help(){ window.open("http://spec.commonmark.org/0.17/"); }
key('ctrl+s', function(){ save(); return false });
key('ctrl+e', function(){ toggle(); return false });
key('ctrl+h', function(){ help(); return false });
e.commands.addCommand({ name: 'save', bindKey: { win: 'Ctrl-S', sender: 'editor|cli' }, exec: save });
e.commands.addCommand({ name: 'toggle', bindKey: { win: 'Ctrl-E', sender: 'editor|cli' }, exec: toggle });
e.commands.addCommand({ name: 'help', bindKey: { win: 'Ctrl-H', sender: 'editor|cli' }, exec: help });
e.commands.removeCommands([
"gotoline", "find", "replace", "replaceAll",
///*"backspace",*/ "blockindent", "blockoutdent", "centerselection", "copylinesdown", "copylinesup", /*"cut",*/ "cut_or_delete",
///*"del",*/ "duplicateSelection", "expandtoline", "find", "findnext", "findprevious", "fold", "foldOther", "foldall", "goToNextError", "goToPreviousError", "golinedown",
//"golineup", "gotoend", "gotoleft", "gotoline", "gotolineend", "gotolinestart", "gotopagedown", "gotopageup", "gotoright", "gotostart", "gotowordleft", "gotowordright",
//"indent", "insertstring", "inserttext", "invertSelection", "joinlines", "jumptomatching", "modifyNumberDown", "modifyNumberUp", "movelinesdown", "movelinesup",
//"outdent", /*"overwrite", "pagedown", "pageup",*/ "passKeysToBrowser", /*"redo",*/ "removeline", "removetolineend", "removetolinestart", "removewordleft", "removewordright",
//"replace", "replaymacro", "scrolldown", "scrollup", "selectOrFindNext", "selectOrFindPrevious", "selectall", "selectdown", "selectleft", "selectlineend", "selectlinestart",
//"selectpagedown", "selectpageup", "selectright", "selecttoend", "selecttolineend", "selecttolinestart", "selecttomatching", "selecttostart", "selectup", "selectwordleft",
//"selectwordright", "showSettingsMenu", "sortlines", "splitline", "toggleBlockComment", "toggleFoldWidget", "toggleParentFoldWidget", "togglecomment", "togglerecording",
//"tolowercase", "touppercase", "transposeletters", /*"undo",*/ "unfold", "unfoldall", 
]);

var ec = e.commands;

$(document).ready(function(){ $("#menu").focus(); });

angular.module("Edit", ['ngCookies'])
	.directive("fileList", ["$http", fileList])
	.controller("Edit", ["$rootScope", "$scope", "$http", Edit])
	.controller("Menu", ["$rootScope", "$scope", "$http", "$cookies", Menu]);

function fileList($http){
	return {
		restrict: 'A',
		link: function(s,e,a){
			$http({method:"GET", url:"/file"})
				.success(function(d){
					d.forEach(function(f){
						var p = window.location.pathname;
						var link = p.length == 1 ? "/file/"+f : "/file"+p+"/"+f;
						e.append("<div class='file'><a href='"+link+"'>"+f+"</a></div>");
					});
				})
				.error(function(){ console.log("Failed to get files:", arguments); });
		}
	};
}

function Edit($rootScope, $scope, $http){
	$scope.toggle = function(){
		if($("#editor").is(":visible")){
			$("#editor").hide();
		} else if($rootScope.pageIsLocked == false) {
			$http({method:'PUT', url:window.location.pathname})
				.success(function(d){
					if(d.editable){
						$rootScope.pageIsLocked = true;
						$("#editor").show();
						e.focus();
					} else {
						$("#editor").hide();
						if(d.reason != null){
							$("#reason").text(d.reason);
							setTimeout(function(){$("#reason").text("");}, 5000);
						}
					}
				})
				.error(function(){ console.log("Failed to PUT on root:", arguments); });
		} else {
			$("#editor").show();
			e.focus();
		}
	}
}

function Menu($rootScope, $scope, $http, $cookies){
	$rootScope.pageIsLocked = false;
	$scope.menuVisible = false;
	$scope.releaseLock = function(){
		$http({method:'PATCH', url:window.location.pathname})
			.success(function(){
				$rootScope.pageIsLocked = false;
				$("#editor").hide();
			})
			.error(function(){ console.log("Failed to release lock on page:", arguments); });
	}
	$scope.toggleMenu = function(){ $scope.menuVisible = !$scope.menuVisible; };
	$scope.editUser = function(){ console.log("Edit user isn't implemented yet"); }
	$scope.form = {};
	$("#password").on("keypress", function(e){
		if(e.keyCode == 13){
			$("#passwordConfirm").focus();
		}
	});
	$("#passwordConfirm").on("keypress", function(e){
		if(e.keyCode == 13){
			$scope.$apply(function(){
				$scope.menuVisible = false;
				$http({method:'PUT', url:'/user', data:$scope.form})
					.success(function(){ console.log("Password changed"); })
					.error(function(){ console.log("Failed to change password:", arguments); });
				$scope.form = {};
			});
		}
	});
	$scope.upload = function(){
		var fd = new FormData();
		fd.append("f", $("#file")[0].files[0]);
		$http({ method: 'POST', url: '/file', data: fd, headers: {'Content-Type': undefined}, transformRequest:angular.identity })
			.success(function(){ console.log("upload worked"); window.location.reload(); })
			.error(function(){ console.log("upload failed:", arguments); });
	}
}

