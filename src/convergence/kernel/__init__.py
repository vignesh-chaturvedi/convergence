"""Thin ctypes bindings to the kernel interfaces Convergence enforces policies with.

These modules only wrap system calls and libseccomp. They make no policy decisions. Every
binding is verified against the running kernel by the live probes in
:mod:`convergence.probe`, never assumed to work.
"""
