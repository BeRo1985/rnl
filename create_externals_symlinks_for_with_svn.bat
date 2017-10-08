@echo off
if not exist externals mkdir externals 2>nul
if not exist externals\pasmp mklink /J externals\pasmp ..\..\PASMP.github\trunk
