package jetbrains.buildserver.sonarplugin;

import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;
import java.io.File;
import java.io.FilenameFilter;
import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import jetbrains.buildServer.RunBuildException;
import jetbrains.buildServer.agent.plugins.beans.PluginDescriptor;
import jetbrains.buildServer.agent.runner.CommandLineBuildService;
import jetbrains.buildServer.agent.runner.JavaCommandLineBuilder;
import jetbrains.buildServer.agent.runner.JavaRunnerUtil;
import jetbrains.buildServer.agent.runner.ProgramCommandLine;
import jetbrains.buildServer.runner.JavaRunnerConstants;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.HttpMethod;
import org.apache.commons.httpclient.UsernamePasswordCredentials;
import org.apache.commons.httpclient.auth.AuthScope;
import org.apache.commons.httpclient.methods.GetMethod;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.xml.sax.Attributes;
import org.xml.sax.SAXException;
import org.xml.sax.helpers.DefaultHandler;

/**
 * Created by Andrey Titov on 4/3/14.
 * <p>
 * SonarQube Runner wrapper process.
 */
public class SQRBuildService extends CommandLineBuildService {
    private static final String BUNDLED_SQR_RUNNER_PATH = "sonar-qube-runner";
    private static final String SQR_RUNNER_PATH_PROPERTY = "teamcity.tool.sonarquberunner";
    private static final Pattern PATTERN_SONAR_RUNNER_JAR = Pattern.compile("/?sonar-runner-dist-(?:([^-]+)(?:-(.*))?)\\.jar$");
    private static final String SONAR_CORE_VERSION = "sonar.core.version";
    private static final Version VERSION_2_5 = new Version("2.5");
    private static final Version VERSION_2_4 = new Version("2.4");
    private static final Version VERSION_5_2 = new Version("5.2");
    @NotNull
    private final PluginDescriptor myPluginDescriptor;
    @NotNull
    private final SonarProcessListener mySonarProcessListener;
    private Version serverVersion;

    public SQRBuildService(@NotNull final PluginDescriptor pluginDescriptor,
                           @NotNull final SonarProcessListener sonarProcessListener) {
        myPluginDescriptor = pluginDescriptor;
        mySonarProcessListener = sonarProcessListener;
    }

    @NotNull
    @Override
    public ProgramCommandLine makeProgramCommandLine() throws RunBuildException {
        final Map<String, String> allParameters = new HashMap<>(getRunnerContext().getRunnerParameters());
        allParameters.putAll(getBuild().getSharedConfigParameters());
        final SQRParametersAccessor accessor = new SQRParametersAccessor(allParameters);

        JavaCommandLineBuilder builder = new JavaCommandLineBuilder();
        builder.setJavaHome(getRunnerContext().getRunnerParameters().get(JavaRunnerConstants.TARGET_JDK_HOME));

        String classpath = getClasspath(accessor);
        Version runnerVersion = findRunnerVersion(classpath);
        String mainClass = "org.sonar.runner.Main";

        if (runnerVersion != null) {
            getLogger().message("Using sonar runner runnerVersion : " + runnerVersion);
            if (runnerVersion.compareTo(VERSION_2_5) >= 0) {
                mainClass = "org.sonar.runner.cli.Main";
            }
        }

        builder.setEnvVariables(getRunnerContext().getBuildParameters().getEnvironmentVariables());
        builder.setSystemProperties(getRunnerContext().getBuildParameters().getSystemProperties());

        builder.setJvmArgs(JavaRunnerUtil.extractJvmArgs(getRunnerContext().getRunnerParameters()));
        builder.setClassPath(classpath);

        builder.setMainClass(mainClass);
        builder.setProgramArgs(composeSQRArgs(accessor, getBuild().getSharedConfigParameters()));
        builder.setWorkingDir(getRunnerContext().getWorkingDirectory().getAbsolutePath());

        final ProgramCommandLine cmd = builder.build();

        getLogger().message("Starting SQR");
        for (String str : cmd.getArguments()) {
            getLogger().message(str);
        }

        return cmd;
    }

    /**
     * @return Classpath for SonarQube Runner
     * @throws SQRJarException
     */
    @NotNull
    private String getClasspath(final @NotNull SQRParametersAccessor accessor) throws SQRJarException {
        final File pluginJar[] = getSQRJar(accessor, myPluginDescriptor.getPluginRoot());
        final StringBuilder builder = new StringBuilder();
        for (final File file : pluginJar) {
            builder.append(file.getAbsolutePath()).append(File.pathSeparatorChar);
        }
        return builder.substring(0, builder.length() - 1);
    }

    private Version findRunnerVersion(String classpath) throws SQRJarException {
        SortedSet<Version> out = new TreeSet<>();
        for (String j : classpath.split("" + File.pathSeparatorChar)) {
            Matcher m = PATTERN_SONAR_RUNNER_JAR.matcher(j.trim());
            boolean match = m.find();
            if (match) {
                out.add(new Version(m.group(1)));
            }
        }
        if (out.isEmpty()) {
            throw new SQRJarException("No sonar runner jar found from " + classpath);
        } else if (out.size() > 1) {
            throw new SQRJarException("Multiple sonar runner jar found from " + classpath);
        }
        return out.last();
    }

    /**
     * Composes SonarQube Runner arguments.
     *
     * @param accessor Parameters to compose arguments from
     * @return List of arguments to be passed to the SQR
     */
    private List<String> composeSQRArgs(@NotNull final SQRParametersAccessor accessor, Map<String, String> sharedConfigParameters) throws SQRJarException {
        final List<String> res = new LinkedList<>();
        Version serverVersion = getServerVersion(accessor);
        addSQRArg(res, "-Dproject.home", ".");
        addSQRArg(res, "-Dsonar.host.url", accessor.getHostUrl());
        if (serverVersion == null || serverVersion.compareTo(VERSION_5_2) < 0) {
            addSQRArg(res, "-Dsonar.jdbc.url", accessor.getJDBCUrl());
            addSQRArg(res, "-Dsonar.jdbc.username", accessor.getJDBCUsername());
            addSQRArg(res, "-Dsonar.jdbc.password", accessor.getJDBCPassword());
        }
        addSQRArg(res, "-Dsonar.projectKey", accessor.getProjectKey());
        addSQRArg(res, "-Dsonar.projectName", accessor.getProjectName());
        addSQRArg(res, "-Dsonar.projectVersion", accessor.getProjectVersion());
        addSQRArg(res, "-Dsonar.sources", accessor.getProjectSources());
        addSQRArg(res, "-Dsonar.tests", accessor.getProjectTests());
        addSQRArg(res, "-Dsonar.binaries", accessor.getProjectBinaries());
        addSQRArg(res, "-Dsonar.modules", accessor.getProjectModules());
        addSQRArg(res, "-Dsonar.password", accessor.getPassword());
        addSQRArg(res, "-Dsonar.login", accessor.getLogin());
        final String additionalParameters = accessor.getAdditionalParameters();
        if (additionalParameters != null) {
            res.addAll(Arrays.asList(additionalParameters.split("\\n")));
        }

        final Set<String> collectedReports = mySonarProcessListener.getCollectedReports();
        if (!collectedReports.isEmpty() && (accessor.getAdditionalParameters() == null || !accessor.getAdditionalParameters().contains("-Dsonar.junit.reportsPath"))) {
            addSQRArg(res, "-Dsonar.dynamicAnalysis", "reuseReports");
            addSQRArg(res, "-Dsonar.junit.reportsPath", collectReportsPath(collectedReports, accessor.getProjectModules()));
        }

        final String jacocoExecFilePath = sharedConfigParameters.get("teamcity.jacoco.coverage.datafile");
        if (jacocoExecFilePath != null) {
            final File file = new File(jacocoExecFilePath);
            if (file.exists() && file.isFile() && file.canRead()) {
                addSQRArg(res, "-Dsonar.java.coveragePlugin", "jacoco");
                addSQRArg(res, "-Dsonar.jacoco.reportPath", jacocoExecFilePath);
            }
        }
        return res;
    }

    /**
     * @param sqrRoot SQR root directory
     * @return SonarQube Runner jar location
     * @throws SQRJarException
     */
    @NotNull
    private File[] getSQRJar(final @NotNull SQRParametersAccessor accessor, final @NotNull File sqrRoot) throws SQRJarException {
        final String path = getRunnerContext().getConfigParameters().get(SQR_RUNNER_PATH_PROPERTY);
        File baseDir;
        if (path != null) {
            baseDir = new File(path);
        } else {
            baseDir = new File(sqrRoot, BUNDLED_SQR_RUNNER_PATH);
        }
        final File libPath = new File(baseDir, "lib");
        if (!libPath.exists()) {
            throw new SQRJarException("SonarQube Runner lib path doesn't exist: " + libPath.getAbsolutePath());
        } else if (!libPath.isDirectory()) {
            throw new SQRJarException("SonarQube Runner lib path is not a directory: " + libPath.getAbsolutePath());
        } else if (!libPath.canRead()) {
            throw new SQRJarException("Cannot read SonarQube Runner lib path: " + libPath.getAbsolutePath());
        }

        final SortedMap<Version, String> runnerJars = new TreeMap<>();

        File[] jars = libPath.listFiles(new FilenameFilter() {

            public boolean accept(File dir, String name) {
                boolean out = name.toLowerCase().endsWith(".jar");
                if (out) {
                    getLogger().message("Found jar : " + name);
                    Matcher m = PATTERN_SONAR_RUNNER_JAR.matcher(name);
                    if (m.find()) {
                        Version jarVersion = new Version(m.group(1));
                        out = matchRequiredSonarRunnerVersion(jarVersion, accessor);
                        if (out) {
                            runnerJars.put(jarVersion, new File(dir, name).getAbsolutePath());
                        }
                    }
                }
                return out;
            }
        });
        if (runnerJars.size() > 1) {
            //Multiple versions compatible, using last one
            Collection<File> tmp = new ArrayList<>();
            //Removing last version from set
            runnerJars.remove(runnerJars.lastKey());
            Set<String> toRemove = new HashSet<>(runnerJars.values());
            //Removing older versions from list of jars
            for (File f : jars) {
                if (!toRemove.remove(f.getAbsolutePath())) {
                    tmp.add(f);
                }
            }
            jars = tmp.toArray(new File[tmp.size()]);
        }
        if (jars.length == 0) {
            throw new SQRJarException("No JAR files found in lib path for server version " + getServerVersion(accessor) + ": " + libPath);
        }
        return jars;
    }

    private Version getServerVersion(SQRParametersAccessor accessor) {
        if (serverVersion == null) {
            String host = accessor.getHostUrl();
            StringBuilder url = new StringBuilder(host);
            if (!host.endsWith("/")) {
                url.append("/");
            }
            url.append("/api/properties/").append(SONAR_CORE_VERSION).append("?format=xml");
            InputStream is = null;
            try {
                HttpClient client = new HttpClient();
                client.getState().setCredentials(AuthScope.ANY, new UsernamePasswordCredentials(accessor.getLogin(), accessor.getPassword()));
                client.getParams().setAuthenticationPreemptive(true);
                HttpMethod m = new GetMethod(url.toString());
                m.setDoAuthentication(true);
                int result = client.executeMethod(m);
                if (result == 200) {
                    try {
                        SAXParserFactory parserFactor = SAXParserFactory.newInstance();
                        SAXParser parser = parserFactor.newSAXParser();
                        SonarServerPropertiesHandler handler = new SonarServerPropertiesHandler();
                        parser.parse(m.getResponseBodyAsStream(), handler);
                        serverVersion = new Version(handler.properties.get(SONAR_CORE_VERSION));
                    } catch (Exception e) {
                        getLogger().buildFailureDescription("Unable to parse xml result to get version from : " + url);
                    }
                } else {
                    getLogger().buildFailureDescription("Unable to connect to server (http " + result + ") to get version from : " + url);
                }
            } catch (MalformedURLException e) {
                getLogger().buildFailureDescription("Unable to use url : " + url);
            } catch (IOException e) {
                getLogger().buildFailureDescription("Unable to connect to server to get version from : " + url);
            } finally {
                if (is != null) {
                    try {
                        is.close();
                    } catch (IOException ioe) {
                        //Nothing to do
                    }
                }
            }
        }
        return serverVersion;
    }

    /**
     * Adds argument only if it's value is not null
     *
     * @param argList Result list of arguments
     * @param key     Argument key
     * @param value   Argument value
     */
    protected static void addSQRArg(@NotNull final List<String> argList, @NotNull final String key, @Nullable final String value) {
        if (!Util.isEmpty(value)) {
            argList.add(key + "=" + value);
        }
    }

    @Nullable
    private String collectReportsPath(Set<String> collectedReports, String projectModules) {
        StringBuilder sb = new StringBuilder();
        final String[] modules = projectModules != null ? projectModules.split(",") : new String[0];
        Set<String> filteredReports = new HashSet<>();
        for (String report : collectedReports) {
            if (!new File(report).exists()) continue;
            for (String module : modules) {
                final int indexOf = report.indexOf(module);
                if (indexOf > 0) {
                    report = report.substring(indexOf + module.length() + 1);
                }
            }
            filteredReports.add(report);
        }

        for (String report : filteredReports) {
            sb.append(report).append(',');
            break; // At the moment sonar.junit.reportsPath doesn't accept several paths
        }
        return sb.length() > 0 ? sb.substring(0, sb.length() - 1) : null;
    }

    private boolean matchRequiredSonarRunnerVersion(Version version, SQRParametersAccessor accessor) {
        Version serverVersion = getServerVersion(accessor);
        boolean out = true;
        if (serverVersion != null) {
            if (serverVersion.compareTo(VERSION_5_2) >= 0) {
                out = version.compareTo(VERSION_2_5) >= 0;
            } else {
                out = version.compareTo(VERSION_2_4) <= 0;
            }
        }
        return out;
    }

    private static class SonarServerPropertiesHandler extends DefaultHandler {
        Map<String, String> properties = new HashMap<>();
        String key;
        String value;
        StringBuilder content;

        @Override
        public void startElement(String uri, String localName, String qName, Attributes attributes) throws SAXException {
            switch (qName) {
                case "key":
                case "value":
                    content = new StringBuilder();
            }
        }

        @Override
        public void endElement(String uri, String localName, String qName) throws SAXException {
            switch (qName) {
                case "key":
                    key = content.toString();
                    break;
                case "value":
                    value = content.toString();
                    break;
                case "property":
                    properties.put(key, value);
                    break;
            }
        }

        @Override
        public void characters(char[] ch, int start, int length) throws SAXException {
            content.append(ch, start, length);
        }
    }

    public static class Version implements Comparable<Version> {

        private final String version;

        public Version(String version) {
            if (version == null)
                throw new IllegalArgumentException("Version can not be null");
            if (!version.matches("[0-9]+(\\.[0-9]+)*"))
                throw new IllegalArgumentException("Invalid version format");
            this.version = version;
        }

        @Override
        public boolean equals(Object that) {
            if (this == that)
                return true;
            if (that == null)
                return false;
            if (this.getClass() != that.getClass())
                return false;
            return this.compareTo((Version) that) == 0;
        }

        @Override
        public int compareTo(Version that) {
            if (that == null)
                return 1;
            String[] thisParts = this.get().split("\\.");
            String[] thatParts = that.get().split("\\.");
            int length = Math.max(thisParts.length, thatParts.length);
            for (int i = 0; i < length; i++) {
                int thisPart = i < thisParts.length ?
                        Integer.parseInt(thisParts[i]) : 0;
                int thatPart = i < thatParts.length ?
                        Integer.parseInt(thatParts[i]) : 0;
                if (thisPart < thatPart)
                    return -1;
                if (thisPart > thatPart)
                    return 1;
            }
            return 0;
        }

        public final String get() {
            return this.version;
        }

        @Override
        public String toString() {
            return get();
        }

    }
}
