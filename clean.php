<?php
	function rrmdir($dir) { 
	   if (is_dir($dir)) { 
		 $objects = scandir($dir); 
		 foreach ($objects as $object) { 
		   if ($object != "." && $object != "..") { 
			 if (filetype($dir."/".$object) == "dir") rrmdir($dir."/".$object); else unlink($dir."/".$object); 
		   } 
		 } 
		 reset($objects); 
		 rmdir($dir); 
	   } 
	}
  $dirs = glob("./*", GLOB_ONLYDIR);
  $now   = time();
  foreach ($dirs as $dir){
	if ($now - filemtime($dir) >= 60 * 15){
		if($dir != "./contents" && $dir != "./log"){
			rrmdir($dir);
		}
	}
  }
?>