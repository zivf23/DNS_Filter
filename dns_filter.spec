# dns_filter.spec
# -*- mode: python ; coding: utf-8 -*-

block_cipher = None

# --- Application Specific ---
app_name = 'DNSFilterApp' # Name of the final .exe
entry_point_script = 'dns_filter_tool.py' # The main script to run

a = Analysis([entry_point_script],
             pathex=['.'],  # Add current directory to path to find dns_filter_pkg
             binaries=[],
             datas=[],      # If you have other data files, add them here
                            # e.g., [('path/to/icon.ico', '.')]
             hiddenimports=[], # If PyInstaller misses any imports, list them here
             hookspath=[],
             runtime_hooks=[],
             excludes=[],
             win_no_prefer_redirects=False,
             win_private_assemblies=False,
             cipher=block_cipher,
             noarchive=False)

# --- Include the dns_filter_pkg ---
# PyInstaller should automatically detect and include 'dns_filter_pkg'
# because it's imported by 'dns_filter_tool.py'.
# If it doesn't, you might need to explicitly add it to `datas` or use `Tree`.
# Example for explicitly adding the package if needed:
# datas_pkg = Tree('dns_filter_pkg', prefix='dns_filter_pkg')
# a.datas += datas_pkg
# However, direct import from the entry point is usually sufficient.

pyz = PYZ(a.pure, a.zipped_data,
             cipher=block_cipher)

exe = EXE(pyz,
          a.scripts,
          [],
          exclude_binaries=True,
          name=app_name, # Use the defined app_name for the .exe
          debug=False,
          bootloader_ignore_signals=False,
          strip=False,
          upx=True, # UPX compression if UPX is installed and in PATH
          console=True, # This is a command-line tool, so console is needed
          # icon='path/to/your/icon.ico', # Optional: path to an icon file
          manifest='''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <assemblyIdentity
    version="1.0.0.0"
    processorArchitecture="*"
    name="CompanyName.ProductName.YourApp"
    type="win32"
  />
  <description>DNS Filter Application</description>
  <dependency>
    <dependentAssembly>
      <assemblyIdentity
        type="win32"
        name="Microsoft.Windows.Common-Controls"
        version="6.0.0.0"
        processorArchitecture="*"
        publicKeyToken="6595b64144ccf1df"
        language="*"
      />
    </dependentAssembly>
  </dependency>
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security>
      <requestedPrivileges>
        <requestedExecutionLevel level="requireAdministrator" uiAccess="false"/>
      </requestedPrivileges>
    </security>
  </trustInfo>
  <compatibility xmlns="urn:schemas-microsoft-com:compatibility.v1">
    <application>
      <supportedOS Id="{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}"/>
      <supportedOS Id="{1f676c76-80e1-4239-95bb-83d0f6d0da78}"/>
      <supportedOS Id="{4a2f28e3-53b9-4441-ba9c-d69d4a4a6e38}"/>
      <supportedOS Id="{35138b9a-5d96-4fbd-8e2d-a2440225f93a}"/>
    </application>
  </compatibility>
</assembly>'''
)

# Optional: If you create a distribution bundle (not just onefile)
# coll = COLLECT(exe,
#                a.binaries,
#                a.zipfiles,
#                a.datas,
#                strip=False,
#                upx=True,
#                name=f'{app_name}_dist_folder')

