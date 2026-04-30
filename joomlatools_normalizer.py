#!/usr/bin/env python3
from __future__ import annotations
import hashlib, json, os, re, sys, tempfile, time, zipfile
import xml.etree.ElementTree as ET
from dataclasses import dataclass, asdict
from typing import List, Optional, Dict

@dataclass
class ExtensionPackage:
    title: str
    type: str
    group: str
    element: str
    version: str
    archive_name: str
    manifest_path: str
    payload_path: str
    payload_root: str
    file_count: int
    source_manifest_sha256: str

@dataclass
class WrapperMetadata:
    min_php: str
    min_joomla: str
    old_docman_floor: str
    success_url: str
    success_text: str
    creation_date: str
    author: str
    author_email: str
    author_url: str
    copyright: str
    license: str
    framework_payload_version: str
    has_framework_downgrade_guard: bool

def fail(msg: str, code: int = 1) -> None:
    print(msg, file=sys.stderr)
    raise SystemExit(code)

def sha256_bytes(data: bytes) -> str:
    h=hashlib.sha256(); h.update(data); return h.hexdigest()

def sha256_file(path: str) -> str:
    h=hashlib.sha256()
    with open(path,'rb') as f:
        for b in iter(lambda:f.read(1024*1024), b''): h.update(b)
    return h.hexdigest()

def xml_text(root: ET.Element, name: str, default: str='') -> str:
    v=root.findtext(name); return v.strip() if v else default

def find_package_manifest(names: List[str], payload_root: str) -> Optional[str]:
    candidates=[n for n in names if n.startswith(payload_root) and n.endswith('.xml') and not n.endswith('/language/en-GB/en-GB.sys.xml')]
    if not candidates: return None
    def score(name: str):
        rel=name[len(payload_root):]; base=os.path.basename(name); preferred=0
        if rel.count('/') == 0: preferred=-10
        elif base.startswith(('com_','pkg_','plg_')): preferred=-5
        return (rel.count('/'), preferred, len(name), name)
    return sorted(candidates, key=score)[0]

def build_extension_definition(z: zipfile.ZipFile, package_path: str, manifest_path: str) -> ExtensionPackage:
    xml_bytes=z.read(manifest_path); root=ET.fromstring(xml_bytes)
    ext_type=root.attrib.get('type','').strip(); group=root.attrib.get('group','').strip()
    title=xml_text(root,'name'); version=xml_text(root,'version'); element=title
    if ext_type == 'plugin':
        m=re.match(r'^plg_([a-z0-9_-]+)_(.+)$', title, re.I)
        if m:
            group=group or m.group(1); element=m.group(2)
        archive_name=f'plg_{group}_{element}.zip'
    else:
        archive_name=f'{title}.zip'
    root_path=f'payload/{package_path.strip("/")}/'
    file_count=sum(1 for i in z.infolist() if i.filename.startswith(root_path) and i.filename != root_path and not i.filename.endswith('/'))
    return ExtensionPackage(title, ext_type, group, element, version, archive_name, manifest_path, package_path, root_path, file_count, sha256_bytes(xml_bytes))

def extract_framework_version(z: zipfile.ZipFile) -> str:
    candidates=[
        'payload/framework/libraries/joomlatools/library/koowa.php',
        'payload/framework/libraries/joomlatools-components/library/koowa.php',
    ]
    for c in candidates:
        try:
            data=z.read(c).decode('utf-8','ignore')
        except KeyError:
            continue
        m=re.search(r"const\s+VERSION\s*=\s*['\"]([^'\"]+)", data, re.I)
        if m: return m.group(1)
    return ''

def parse_wrapper_metadata(z: zipfile.ZipFile, payload_manifest: dict) -> WrapperMetadata:
    wrapper_xml=ET.fromstring(z.read('joomlatools_installer.xml'))
    script=z.read('script.php').decode('utf-8','ignore')
    def rx(pattern: str, default: str) -> str:
        m=re.search(pattern, script, re.S); return m.group(1) if m else default
    return WrapperMetadata(
        min_php=rx(r"\$minimum_php_version\s*=\s*'([^']+)'", '7.3'),
        min_joomla=rx(r"version_compare\(JVERSION,\s*'([^']+)',\s*'<'\)", '3.10'),
        old_docman_floor=rx(r"version_compare\(\$docman_version,\s*'([^']+)',\s*'<'\)", '2.1.5'),
        success_url=str(payload_manifest.get('success_url') or 'index.php'),
        success_text=str(payload_manifest.get('success_text') or 'Go to extension'),
        creation_date=xml_text(wrapper_xml,'creationDate'),
        author=xml_text(wrapper_xml,'author','Joomlatools'),
        author_email=xml_text(wrapper_xml,'authorEmail',''),
        author_url=xml_text(wrapper_xml,'authorUrl',''),
        copyright=xml_text(wrapper_xml,'copyright',''),
        license=xml_text(wrapper_xml,'license',''),
        framework_payload_version=extract_framework_version(z),
        has_framework_downgrade_guard=('Prevent Framework downgrade' in script or '$payload_koowa' in script),
    )

def phpq(s: str) -> str:
    return s.replace('\\','\\\\').replace("'","\\'")

def write_subzip_bytes(z: zipfile.ZipFile, ext: ExtensionPackage) -> bytes:
    tmp=tempfile.NamedTemporaryFile(delete=False); tmp.close()
    try:
        with zipfile.ZipFile(tmp.name, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=9) as out:
            for info in z.infolist():
                name=info.filename
                if not name.startswith(ext.payload_root) or name == ext.payload_root: continue
                rel=name[len(ext.payload_root):]
                if not rel: continue
                zi=zipfile.ZipInfo(rel if not name.endswith('/') else (rel if rel.endswith('/') else rel+'/'))
                zi.date_time=info.date_time; zi.external_attr=info.external_attr; zi.comment=info.comment; zi.extra=info.extra
                zi.compress_type=zipfile.ZIP_DEFLATED
                out.writestr(zi, b'' if name.endswith('/') else z.read(name))
        with open(tmp.name,'rb') as f: return f.read()
    finally:
        try: os.unlink(tmp.name)
        except OSError: pass

def manifest_xml(pkg_element: str, version: str, exts: List[ExtensionPackage], meta: WrapperMetadata) -> str:
    package_name=pkg_element[4:] if pkg_element.startswith('pkg_') else pkg_element
    files=[]
    for e in exts:
        attrs=[f'type="{e.type}"']
        if e.group: attrs.append(f'group="{e.group}"')
        attrs.append(f'id="{e.element}"')
        files.append(f'        <file {" ".join(attrs)}>{e.archive_name}</file>')
    return '\n'.join(['<?xml version="1.0" encoding="utf-8"?>','<extension type="package" method="upgrade" version="3.0">',f'    <name>{pkg_element}</name>',f'    <packagename>{package_name}</packagename>',f'    <author>{meta.author}</author>',f'    <creationDate>{meta.creation_date}</creationDate>',f'    <copyright>{meta.copyright}</copyright>',f'    <license>{meta.license}</license>',f'    <authorEmail>{meta.author_email}</authorEmail>',f'    <authorUrl>{meta.author_url}</authorUrl>',f'    <version>{version or "1.0.0"}</version>','    <description>Standard Joomla package generated from a Joomlatools wrapper installer while preserving payload contents and installer checks.</description>','    <scriptfile>script.php</scriptfile>','    <blockChildUninstall>false</blockChildUninstall>','    <files>',*files,'    </files>','</extension>',''])

PHP_TEMPLATE=r'''<?php
defined('_JEXEC') or die;

class {class_name}
{{
    protected $minimumPhpVersion = '{min_php}';
    protected $minimumJoomlaVersion = '{min_joomla}';
    protected $oldDocmanFloor = '{old_docman_floor}';
    protected $successUrl = '{success_url}';
    protected $successText = '{success_text}';
    protected $frameworkPayloadVersion = '{framework_payload_version}';
    protected $enforceFrameworkDowngradeGuard = {framework_guard};
    protected $packageElement = '{pkg_element}';

    protected function getAbortHandler($adapter)
    {{
        if (is_object($adapter) && method_exists($adapter, 'getParent')) {{
            $parent = $adapter->getParent();
            if (is_object($parent) && method_exists($parent, 'abort')) {{ return $parent; }}
        }}
        return $adapter;
    }}

    protected function abortInstall($adapter, $message)
    {{
        $target = $this->getAbortHandler($adapter);
        if (is_object($target) && method_exists($target, 'abort')) {{ $target->abort($message); }}
        try {{ \Joomla\CMS\Factory::getApplication()->enqueueMessage($message, 'error'); }} catch (\Throwable $e) {{}} catch (\Exception $e) {{}}
        return false;
    }}

    protected function getComponentVersion($component)
    {{
        try {{
            $db = \Joomla\CMS\Factory::getDbo();
            $query = $db->getQuery(true)
                ->select($db->quoteName('manifest_cache'))
                ->from($db->quoteName('#__extensions'))
                ->where($db->quoteName('type') . ' = ' . $db->quote('component'))
                ->where($db->quoteName('element') . ' = ' . $db->quote('com_' . $component));
            $result = $db->setQuery($query)->loadResult();
            if ($result) {{
                $manifest = new \Joomla\Registry\Registry($result);
                return $manifest->get('version', null);
            }}
        }} catch (\Throwable $e) {{}} catch (\Exception $e) {{}}
        return null;
    }}

    protected function getJoomlaVersion()
    {{
        return defined('JVERSION') ? JVERSION : '0.0.0';
    }}

    protected function getCurrentFrameworkVersion()
    {{
        $candidates = array(
            JPATH_LIBRARIES . '/joomlatools/library/koowa.php',
            JPATH_LIBRARIES . '/joomlatools-components/library/koowa.php'
        );
        foreach ($candidates as $file) {{
            if (is_file($file)) {{
                $contents = file_get_contents($file);
                if (preg_match("#const\s+VERSION\s*=\s*['\"](.*?)['\"]#i", $contents, $matches)) {{
                    return $matches[1];
                }}
            }}
        }}
        return null;
    }}

    protected function isCompatPluginEnabled($joomlaVersion)
    {{
        if (!class_exists('\\Joomla\\CMS\\Plugin\\PluginHelper')) {{ return true; }}
        if (version_compare($joomlaVersion, '5.0', '<')) {{ return true; }}
        if (version_compare($joomlaVersion, '6.0', '<')) {{ return \Joomla\CMS\Plugin\PluginHelper::isEnabled('behaviour', 'compat'); }}
        return \Joomla\CMS\Plugin\PluginHelper::isEnabled('behaviour', 'compat6');
    }}

    public function preflight($type, $adapter)
    {{
        $docmanVersion = $this->getComponentVersion('docman');
        if ($docmanVersion && version_compare($docmanVersion, $this->oldDocmanFloor, '<')) {{
            $warning = 'Your site has DOCman %s installed. Please upgrade DOCman first to 2.1.6 and then to 3.0 in this order. This will ensure your data is properly migrated. We advise you to read our <a target="_blank" href="https://www.joomlatools.com/extensions/docman/documentation/upgrading/">upgrading guide</a>.';
            return $this->abortInstall($adapter, sprintf($warning, $docmanVersion));
        }}
        if (version_compare(PHP_VERSION, $this->minimumPhpVersion, '<')) {{
            return $this->abortInstall($adapter, sprintf('Your server is running PHP %s. This version is end of life and no longer supported. It contains possible bugs and security vulnerabilities. Please contact your host and ask them to upgrade PHP to at least %s version on your server.', PHP_VERSION, $this->minimumPhpVersion));
        }}
        $joomlaVersion = $this->getJoomlaVersion();
        if (version_compare($joomlaVersion, $this->minimumJoomlaVersion, '<')) {{
            return $this->abortInstall($adapter, sprintf('Your site is running Joomla %s which is an unsupported version. Please upgrade Joomla to the latest version or at least to Joomla %s first.', $joomlaVersion, $this->minimumJoomlaVersion));
        }}
        if ($this->enforceFrameworkDowngradeGuard && $this->frameworkPayloadVersion) {{
            $currentVersion = $this->getCurrentFrameworkVersion();
            if ($currentVersion && version_compare($this->frameworkPayloadVersion, $currentVersion, '<')) {{
                return $this->abortInstall($adapter, sprintf('Your site is running Joomlatools Framework %s. This package ships version %s which is older and cannot be installed. Please use a newer version of the package.', $currentVersion, $this->frameworkPayloadVersion));
            }}
        }}
        if (!$this->isCompatPluginEnabled($joomlaVersion)) {{
            $pluginName = version_compare($joomlaVersion, '6.0', '>=') ? 'Behaviour - Backward Compatibility 6' : 'Behaviour - Backward Compatibility';
            $url = 'index.php?option=com_plugins&view=plugins&filter_folder=behaviour';
            return $this->abortInstall($adapter, 'This component requires \' . $pluginName . '\' plugin to be enabled. Please go to <a href="' . $url . '">Plugin Manager</a>, enable <strong>' . $pluginName . '</strong> and try again.');
        }}
        return true;
    }}


    protected function cleanupPackageRegistration()
    {{
        try {{
            $db = \Joomla\CMS\Factory::getDbo();
            $elements = array($this->packageElement);
            if (strpos($this->packageElement, 'pkg_') === 0) {{
                $elements[] = substr($this->packageElement, 4);
            }}
            $quoted = array();
            foreach (array_unique($elements) as $element) {{
                if ($element !== '') {{ $quoted[] = $db->quote($element); }}
            }}
            if ($quoted) {{
                $query = $db->getQuery(true)
                    ->delete($db->quoteName('#__extensions'))
                    ->where($db->quoteName('type') . ' = ' . $db->quote('package'))
                    ->where($db->quoteName('element') . ' IN (' . implode(',', $quoted) . ')');
                $db->setQuery($query)->execute();
            }}
        }} catch (\Throwable $e) {{}} catch (\Exception $e) {{}}

        try {{
            if (class_exists('\\Joomla\\CMS\\Filesystem\\File')) {{
                $files = array(JPATH_ADMINISTRATOR . '/manifests/packages/' . $this->packageElement . '.xml');
                if (strpos($this->packageElement, 'pkg_') === 0) {{
                    $files[] = JPATH_ADMINISTRATOR . '/manifests/packages/' . substr($this->packageElement, 4) . '.xml';
                }}
                foreach (array_unique($files) as $file) {{
                    if (is_file($file)) {{ \Joomla\CMS\Filesystem\File::delete($file); }}
                }}
            }}
        }} catch (\Throwable $e) {{}} catch (\Exception $e) {{}}
    }}

    public function postflight($type, $adapter)
    {{
        if ($type === 'discover_install') {{ return true; }}
        try {{
            $app = \Joomla\CMS\Factory::getApplication();
            $app->setUserState('com_installer.redirect_url', $this->successUrl);
            $app->enqueueMessage($this->successText, 'message');
        }} catch (\Throwable $e) {{}} catch (\Exception $e) {{}}
        try {{
            $target = $this->getAbortHandler($adapter);
            if (is_object($target) && method_exists($target, 'setRedirectUrl')) {{ $target->setRedirectUrl($this->successUrl); }}
        }} catch (\Throwable $e) {{}} catch (\Exception $e) {{}}
        if ($type === 'install' || $type === 'update') {{
            $this->cleanupPackageRegistration();
        }}

        return true;
    }}
}}
'''

def package_script(pkg_class: str, meta: WrapperMetadata, pkg_element: str) -> str:
    return PHP_TEMPLATE.format(class_name=pkg_class, min_php=phpq(meta.min_php), min_joomla=phpq(meta.min_joomla), old_docman_floor=phpq(meta.old_docman_floor), success_url=phpq(meta.success_url), success_text=phpq(meta.success_text), framework_payload_version=phpq(meta.framework_payload_version), framework_guard='true' if meta.has_framework_downgrade_guard else 'false', pkg_element=phpq(pkg_element))

def readme(pkg_element: str, exts: List[ExtensionPackage], meta: WrapperMetadata, outname: str) -> str:
    lines=[f'Generated package: {outname}',f'Package element: {pkg_element}','','Preserved payload packages:']
    for e in exts: lines.append(f'- {e.archive_name} ({e.type}: {e.title} {e.version}, files: {e.file_count})')
    lines += ['','Wrapper behavior recreated:','- DOCman old-version floor check','- Minimum PHP version check','- Minimum Joomla version check','- Joomla 5/6 backward compatibility plugin requirement',f'- Success redirect URL: {meta.success_url}',f'- Success message: {meta.success_text}']
    if meta.has_framework_downgrade_guard: lines.append(f'- Framework downgrade guard using bundled framework version {meta.framework_payload_version}')
    lines += ['','Wrapper-only behavior intentionally omitted:','- Temporary com_joomlatools_installer component','- AJAX progress UI / staged JSON endpoint','- Self-destruct uninstall of the temporary installer component']
    return '\n'.join(lines)+'\n'

def main() -> int:
    if len(sys.argv)<2: fail(f'Usage: {os.path.basename(sys.argv[0])} input.zip [output.zip]')
    input_zip=sys.argv[1]
    if not os.path.isfile(input_zip): fail(f'Input ZIP not found: {input_zip}')
    output_zip=sys.argv[2] if len(sys.argv)>2 else None
    with zipfile.ZipFile(input_zip,'r') as z:
        names=z.namelist()
        for required in ('payload/manifest.json','joomlatools_installer.xml','script.php'):
            if required not in names: fail(f'Missing required file: {required}')
        payload_manifest=json.loads(z.read('payload/manifest.json').decode('utf-8'))
        entries=payload_manifest.get('packages')
        if not isinstance(entries,list) or not entries: fail('Invalid payload/manifest.json: packages missing')
        meta=parse_wrapper_metadata(z,payload_manifest)
        exts=[]; extension_bytes={}; main_component=None
        for entry in entries:
            package_path=str(entry.get('path','')).strip('/')
            if not package_path: fail('Payload entry missing path')
            manifest=find_package_manifest(names, f'payload/{package_path}/')
            if manifest is None: fail(f'Could not find manifest XML in payload/{package_path}/')
            ext=build_extension_definition(z, package_path, manifest)
            exts.append(ext)
            if ext.type=='component' and main_component is None: main_component=ext
            extension_bytes[ext.archive_name]=write_subzip_bytes(z, ext)
        main_name=main_component.element if main_component else 'joomlatools'
        slug=re.sub(r'^com_','',main_name)
        pkg_element=f'pkg_{slug}'; pkg_class=f'{pkg_element}InstallerScript'
        package_version=main_component.version if main_component and main_component.version else '1.0.0'
        if output_zip is None:
            output_zip=os.path.join(os.path.dirname(os.path.abspath(input_zip)), f'{main_name}_normal_v4.zip')
        report={'package':pkg_element,'class_name':pkg_class,'source_file':os.path.basename(input_zip),'source_sha256':sha256_file(input_zip),'generated_utc':time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),'wrapper_metadata':asdict(meta),'extensions':[]}
        for e in exts:
            report['extensions'].append({**asdict(e),'archive_sha256':sha256_bytes(extension_bytes[e.archive_name]),'archive_size':len(extension_bytes[e.archive_name])})
        with zipfile.ZipFile(output_zip,'w',compression=zipfile.ZIP_DEFLATED, compresslevel=9) as out:
            for e in exts: out.writestr(e.archive_name, extension_bytes[e.archive_name])
            out.writestr(f'{pkg_element}.xml', manifest_xml(pkg_element, package_version, exts, meta))
            out.writestr('script.php', package_script(pkg_class, meta, pkg_element))
            out.writestr('conversion-report.json', json.dumps(report, indent=2))
            out.writestr('README-normalized-package.txt', readme(pkg_element, exts, meta, os.path.basename(output_zip)))
    print(f'Created: {output_zip}')
    print(f'SHA256: {sha256_file(output_zip)}')
    return 0
if __name__=='__main__':
    _code = main()
    sys.stdout.flush()
    sys.stderr.flush()
    os._exit(_code)
