import Options, Utils, sys
from shutil import copy, rmtree
from os import unlink, popen
from os.path import exists, islink

srcdir = '.'
blddir = 'build'
VERSION = '0.0.1'
name = 'rsaBinding'

def set_options(ctx):
    ctx.tool_options('compiler_cxx')

def configure(ctx):
    ctx.check_tool('compiler_cxx')
    ctx.check_tool('node_addon')

def build(ctx):
    t = ctx.new_task_gen('cxx', 'shlib', 'node_addon')
    t.target = name
    t.source = 'node_rsa.cc'

def shutdown():
    t = name + '.node'
    if Options.commands['clean']:
        if islink(t): unlink(t)
        if exists('build'): rmtree('build')
    if Options.commands['build']:
        if exists('build/default/' + t) and not exists(t):
            symlink('build/default/' + t, t)
        if exists('build/Release/' + t) and not exists(t):
            symlink('build/Release/' + t, t)
