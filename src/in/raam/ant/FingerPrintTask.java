package in.raam.ant;

import java.io.*;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.CRC32;
import java.util.zip.CheckedInputStream;

import org.apache.tools.ant.*;
import org.apache.tools.ant.types.FileSet;

/**
 * Original Source: https://github.com/Ramasubramanian/ant-fingerprint-task
 * Custom ANT task to fingerprint static resources like CSS, JS, Image files
 * etc. with file checksums to enable dynamic caching in web-servers as
 * described in https://developers.google.com/speed/docs/best-practices/caching,
 * the task will take of reverting file changes and resource name changes back
 * to original after child tasks like WAR, static content TAR creation is
 * completed <br/>
 * <b>Declaration in build.xml</b>
 * 
 * <pre>
 *       	&lt;taskdef name="fingerprint" classname="in.raam.ant.FingerPrintTask" classpath="${CLASSPATH}/ant-fingerprint.jar"/>
 * </pre>
 * 
 * <b>Usage in tasks</b>
 * 
 * <pre>
 * 	&lt;target name="execute" depends="declare">
 * 		&lt;fingerprint docroot="${PROJECT_ROOT}/docroot" extensions="js,css">
 * 			&lt;fileset dir="${PROJECT_ROOT}">
 * 				&lt;include name="...."/>
 * 				&lt;include name="...."/>
 * 				&lt;exclude name="...."/>
 * 			&lt;fileset>
 * 			&lt;!--Child tasks like WAR and TAR creation-->	
 * 			.
 * 			.
 * 			.			
 * 		&lt;/fingerprint>		
 * 	&lt;/target>
 * </pre>
 * 
 * Patterns for extracting static resource references used from
 * https://code.google.com/p/maven-fingerprint-plugin
 * 
 * @author raam
 * 
 *         Modified 12/18/2013 - Barry M. Tofteland - added try/finally and
 *         option to specify fingerprint value to be used instead of checksum.
 *         Also moved fingerprint to end of file name.
 * 
 */
public class FingerPrintTask extends Task implements TaskContainer {

	static class FingerPrint {
		final String fileName;
		final String checkSum;
		final String absoluteName;

		FingerPrint(String fileName, String checkSum, String absoluteName) {
			this.fileName = fileName;
			this.checkSum = checkSum;
			this.absoluteName = absoluteName;
		}
	}

	private static final String FS = File.separator;
	private static final int BUFFER_SIZE = 1024 * 8; // 8 KB
	private static final Pattern[] PATTERNS = { Pattern.compile("(<link.*?href=\")(.*?)(\".*?>)"),
			Pattern.compile("(\")([^\\s]*?\\.js)(\")"), Pattern.compile("(<img.*?src=\")(.*?)(\".*?>)"),
			Pattern.compile("(url\\(\")(.*?)(\"\\))") };

	private String docroot;
	private String[] extensions;
	private boolean enabled = true;
	private List<FileSet> fileSets = new ArrayList<FileSet>();
	private List<Task> childTasks = new ArrayList<Task>();
	private Map<String, FingerPrint> fingerPrintCache = new HashMap<String, FingerPrint>();
	private String fileVersion;// optional to use instead of checksum

	public boolean isEnabled() {
		return enabled;
	}

	public void setEnabled(boolean enabled) {
		this.enabled = enabled;
	}

	public void addTask(Task task) {
		childTasks.add(task);
	}

	public String[] getExtensions() {
		return extensions;
	}

	public void setExtensions(String extensions) {
		this.extensions = extensions.split(",\\s*");
	}

	public String getDocroot() {
		return docroot;
	}

	public void setDocroot(String docroot) {
		this.docroot = docroot;
	}

	public void addFileSet(FileSet fileSet) {
		fileSets.add(fileSet);
	}

	public void execute() throws BuildException {
		log("Fingerprinting enabled : " + enabled);
		try {
			if (enabled) {
				// identify used static resources and fingerprint them
				log("Starting fingerprinting of used static resources!", Project.MSG_INFO);
				doExecute();
				logResourceNames();
			}
			log("Executing child tasks!", Project.MSG_INFO);
			// execute child tasks
			for (Task childTask : childTasks) {
				childTask.perform();
			}
		} finally {
			if (enabled) {
				// post process - change and rename files back to original state
				postExecute();
			}
		}
	}

	private void logResourceNames() {
		for (FingerPrint fingerPrint : fingerPrintCache.values()) {
			log(String.format("Fingerprinted static resource %s with checksum %s", fingerPrint.absoluteName, fingerPrint.checkSum),
					Project.MSG_INFO);
		}
	}

	private void doExecute() throws BuildException {
		File sourceFile;
		int length;
		StringBuilder contents;
		DirectoryScanner dScanner;
		try {
			log("Docroot location : " + docroot, Project.MSG_INFO);
			log("Resource extensions : " + Arrays.deepToString(extensions));
			for (FileSet fs : fileSets) {
				dScanner = fs.getDirectoryScanner(getProject());
				for (String fileName : dScanner.getIncludedFiles()) {
					sourceFile = new File(dScanner.getBasedir(), fileName);
					log("Scanning for references in file : " + sourceFile.getAbsolutePath(), Project.MSG_DEBUG);
					contents = contents(sourceFile);
					length = contents.length();
					for (Pattern pattern : PATTERNS) {
						contents = findAndReplace(pattern, contents);
					}
					// write file only if contents are changed
					if (contents.length() != length) {
						write(contents, sourceFile);
					}
				}
			}
		} catch (Exception e) {
			throw new BuildException(e);
		}
	}

	private void postExecute() throws BuildException {
		File sourceFile;
		int length;
		StringBuilder contents;
		DirectoryScanner dScanner;
		Map<String, String> revertMap = prepareRevertNameMapping(fingerPrintCache);
		try {
			log("Reverting fingerprint changes in referenced files", Project.MSG_INFO);
			for (FileSet fs : fileSets) {
				dScanner = fs.getDirectoryScanner(getProject());
				for (String fileName : dScanner.getIncludedFiles()) {
					sourceFile = new File(dScanner.getBasedir(), fileName);
					contents = contents(sourceFile);
					length = contents.length();
					contents = revertFileNames(contents, revertMap);
					// write file only if contents are changed
					if (contents.length() != length) {
						write(contents, sourceFile);
					}
				}
			}
			log("Reverting fingerprint changes in resource names!", Project.MSG_INFO);
			revertResourceNames(fingerPrintCache);
		} catch (Exception e) {
			throw new BuildException(e);
		}
	}

	private void revertResourceNames(Map<String, FingerPrint> fingerPrintCache) {
		String folder;
		File resource, newResource;
		for (FingerPrint fingerPrint : fingerPrintCache.values()) {
			newResource = new File(fingerPrint.absoluteName);
			folder = dirname(newResource);
			resource = new File(folder, newName(fingerPrint.checkSum, fingerPrint.fileName));
			log(String.format("Renaming file %s to %s", resource.getAbsolutePath(), newResource.getAbsolutePath()), Project.MSG_DEBUG);
			resource.renameTo(newResource);
			// delete old file
			resource.delete();
		}
	}

	private Map<String, String> prepareRevertNameMapping(Map<String, FingerPrint> fingerPrintCache) {
		Map<String, String> retMap = new HashMap<String, String>();
		for (FingerPrint fingerPrint : fingerPrintCache.values()) {
			retMap.put(newName(fingerPrint.checkSum, fingerPrint.fileName), fingerPrint.fileName);
		}
		return retMap;
	}

	private StringBuilder revertFileNames(StringBuilder contents, Map<String, String> names) {
		for (Map.Entry<String, String> name : names.entrySet()) {
			contents = replaceAll(contents, name.getKey(), name.getValue());
		}
		return contents;
	}

	private StringBuilder replaceAll(StringBuilder builder, String from, String to) {
		int index = builder.indexOf(from);
		while (index != -1) {
			builder.replace(index, index + from.length(), to);
			index += to.length(); // Move to the end of the replacement
			index = builder.indexOf(from, index);
		}
		return builder;
	}

	private StringBuilder contents(File f) throws Exception {
		StringBuilder buffer = new StringBuilder();
		BufferedReader fReader = new BufferedReader(new FileReader(f), BUFFER_SIZE);
		int c;
		try {
			while ((c = fReader.read()) != -1) {
				buffer.append((char) c);
			}
		} finally {
			fReader.close();
		}
		return buffer;
	}

	private void write(CharSequence contents, File f) throws Exception {
		log("Writing file : " + f.getAbsolutePath(), Project.MSG_DEBUG);
		BufferedWriter bWriter = new BufferedWriter(new FileWriter(f), BUFFER_SIZE);
		bWriter.append(contents);
		bWriter.flush();
		bWriter.close();
	}

	private StringBuilder findAndReplace(Pattern pattern, StringBuilder fileContents) throws Exception {
		StringBuffer replaced = new StringBuffer();
		Matcher matcher = pattern.matcher(fileContents);
		String link, fileName, replacement;
		FingerPrint fPrint;
		File resource;
		while (matcher.find()) {
			link = matcher.group(2);
			if (replaceable(link)) {
				fileName = fileName(link);
				fPrint = fingerPrintCache.get(fileName);
				if (fPrint == null) {
					resource = new File(docroot, fileName);
					fPrint = new FingerPrint(fileName, checksum(resource), resource.getAbsolutePath());
					fingerPrintCache.put(fileName, fPrint);
					renameResource(resource, fPrint.checkSum);
				}
				replacement = newName(fPrint.checkSum, fPrint.fileName);
				log(String.format("Replacing %s with %s", fileName, replacement), Project.MSG_VERBOSE);
				matcher.appendReplacement(replaced, "$1" + link.replaceAll(fileName, replacement) + "$3");
			}
		}
		matcher.appendTail(replaced);
		return new StringBuilder(replaced);
	}

	private void renameResource(File file, String checksum) {
		String folder = dirname(file);
		File dest = new File(folder, newName(checksum, file.getName()));
		log(String.format("Renaming file %s to %s", file.getAbsolutePath(), dest.getAbsolutePath()), Project.MSG_DEBUG);
		file.renameTo(dest);
		// delete old file
		file.delete();
	}

	private String newName(String checksum, String fileName) {
		String DOT = ".";
		String baseName = fileName.contains(DOT) ? fileName.substring(0, fileName.lastIndexOf(DOT)) : fileName;
		String extension = fileName.contains(DOT) ? fileName.substring(fileName.lastIndexOf(DOT)) : "";
		// return checksum + fileName;
		return baseName + checksum + extension;
	}

	private String dirname(File file) {
		int index = file.getAbsolutePath().lastIndexOf(FS);
		return file.getAbsolutePath().substring(0, index);
	}

	private String checksum(File file) throws Exception {

		if (fileVersion != null) {
			return fileVersion;
		} else {
			if (!file.exists()) {
				log(String.format("File %s does not exists to generate checksum", file.getAbsolutePath()), Project.MSG_WARN);
				return "";
			}
			CheckedInputStream cis = null;
			try {
				// Calculate the CRC-32 checksum of this file
				cis = new CheckedInputStream(new FileInputStream(file), new CRC32());
				byte[] tempBuf = new byte[128];
				while (cis.read(tempBuf) >= 0) {
				}
				Long checksum = cis.getChecksum().getValue();
				return checksum.toString();
			} finally {
				cis.close();
			}
		}
	}

	private boolean replaceable(String link) {
		for (String extension : extensions) {
			if (link.endsWith("." + extension)) {
				return true;
			}
		}
		return false;
	}

	private String fileName(String link) {
		String[] arr = link.split("/");
		return arr[arr.length - 1];
	}

	/**
	 * The file version will be used instead of a checksum if it is set.
	 * 
	 * @param fileVersion
	 *            the fileVersion to set
	 */
	public void setFileVersion(String fileVersion) {
		this.fileVersion = fileVersion;
	}

	/**
	 * @return the fileVersion
	 */
	public String getFileVersion() {
		return fileVersion;
	}
}
