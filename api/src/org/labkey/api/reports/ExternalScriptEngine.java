/*
 * Copyright (c) 2008-2014 LabKey Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.labkey.api.reports;

import org.jetbrains.annotations.Nullable;
import org.labkey.api.util.ExceptionUtil;
import org.labkey.api.util.FileUtil;
import org.labkey.api.reports.report.r.ParamReplacementSvc;

import javax.script.*;
import java.io.*;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/*
* User: Karl Lum
* Date: Dec 2, 2008
* Time: 4:33:23 PM
*/
public class ExternalScriptEngine extends AbstractScriptEngine
{
    /**
     * external script engines rely on the file system to exchange data between the server and script process,
     * the working directory is the folder where files used to run a single instance of a script will appear.
     */
    public static final String WORKING_DIRECTORY = "external.script.engine.workingDirectory";
    public static final String PARAM_REPLACEMENT_MAP = "external.script.engine.replacementMap";
    public static final String PARAM_SCRIPT = "scriptFile";
    public static final String SCRIPT_PATH = "scriptPath";
    public static final String SCRIPT_NAME_REPLACEMENT = "${scriptName}";
    /** The location of the post-replacement script file */
    public static final String REWRITTEN_SCRIPT_FILE = "rewrittenScriptFile";

    public static final String DEFAULT_WORKING_DIRECTORY = "ExternalScript";
    private static final Pattern scriptCmdPattern = Pattern.compile("'([^']+)'|\\\"([^\\\"]+)\\\"|(^[^\\s]+)|(\\s[^\\s^'^\\\"]+)");

    private File _workingDirectory;

    protected ExternalScriptEngineDefinition _def;
    protected Writer _originalWriter;

    public ExternalScriptEngine(ExternalScriptEngineDefinition def)
    {
        _def = def;
        _originalWriter = getContext().getWriter();
    }

    public ScriptEngineFactory getFactory()
    {
        return new ExternalScriptEngineFactory(_def);
    }

    private boolean isBinary(File file)
    {
        String ext = FileUtil.getExtension(file);

        if ("jar".equalsIgnoreCase(ext)) return true;
        if ("class".equalsIgnoreCase(ext)) return true;
        if ("exe".equalsIgnoreCase(ext)) return true;

        return false;
    }

    public Object eval(String script, ScriptContext context) throws ScriptException
    {
        List<String> extensions = getFactory().getExtensions();

        if (!extensions.isEmpty())
        {
            // write out the script file to disk using the first extension as the default
            File scriptFile = writeScriptFile(script, context, extensions);
            return eval(scriptFile, context);
        }
        else
            throw new ScriptException("There are no file name extensions registered for this ScriptEngine : " + getFactory().getLanguageName());
    }

    protected Object eval(File scriptFile, ScriptContext context) throws ScriptException
    {
        String[] params = formatCommand(scriptFile, context);
        ProcessBuilder pb = new ProcessBuilder(params);
        pb = pb.directory(getWorkingDir(context));

        StringBuffer output = new StringBuffer();

        int exitCode = runProcess(context, pb, output);
        if (exitCode != 0)
        {
            throw new ScriptException("An error occurred when running the script '" + scriptFile.getName () + "', exit code: " + exitCode + ").\n" + output.toString());
        }
        else
            return output.toString();
    }

    public Object eval(Reader reader, ScriptContext context) throws ScriptException
    {
        BufferedReader br = new BufferedReader(reader);

        try {
            String l;
            StringBuffer sb = new StringBuffer();
            while ((l = br.readLine()) != null)
            {
                sb.append(l);
                sb.append('\n');
            }
            return eval(sb.toString(), context);
        }
        catch (IOException ioe)
        {
            ExceptionUtil.logExceptionToMothership(null, ioe);
        }
        finally
        {
            try {br.close();} catch(IOException ignored) {}
        }
        return null;
    }

    public Bindings createBindings()
    {
        return new SimpleBindings();
    }

    protected File getWorkingDir(ScriptContext context)
    {
        if (_workingDirectory == null)
        {
            Bindings bindings = context.getBindings(ScriptContext.ENGINE_SCOPE);
            if (bindings.containsKey(WORKING_DIRECTORY))
            {
                String dir = (String)bindings.get(WORKING_DIRECTORY);
                _workingDirectory = new File(dir);
            }
            else
            {
                File tempDir = new File(System.getProperty("java.io.tmpdir"));
                _workingDirectory = new File(tempDir, DEFAULT_WORKING_DIRECTORY);
            }

            if (!_workingDirectory.exists())
                _workingDirectory.mkdirs();
        }
        return _workingDirectory;
    }

    /**
     * Returns the external script command to run given the specified script file. The
     * command must be in the form that is acceptable to ProcessBuilder.
     *
     * @return an array of command parameters
     */
    protected String[] formatCommand(File scriptFile, ScriptContext context) throws ScriptException
    {
        List<String> params = new ArrayList<>();
        String exe = _def.getExePath();
        String cmd = _def.getExeCommand();

        params.add(exe);

        String scriptFilePath = scriptFile.getAbsolutePath();

        try {
            // see if the command contains parameter substitutions
            if (cmd != null)
            {
                int idx = cmd.indexOf('%');
                if (idx != -1)
                    cmd = String.format(cmd, scriptFilePath);

                // process any replacements specified in the script context
                Bindings bindings = context.getBindings(ScriptContext.ENGINE_SCOPE);
                if (bindings.containsKey(PARAM_REPLACEMENT_MAP))
                {
                    for (Map.Entry<String, String> param : ((Map<String, String>)bindings.get(PARAM_REPLACEMENT_MAP)).entrySet())
                    {
                        cmd = ParamReplacementSvc.get().processInputReplacement(cmd, param.getKey(), param.getValue());
                    }
                }

                // process the script file replacement
                boolean specifiedScript = false;
                if (cmd.indexOf(PARAM_SCRIPT) != -1)
                {
                    specifiedScript = true;
                    cmd = ParamReplacementSvc.get().processInputReplacement(cmd, PARAM_SCRIPT, scriptFilePath.replaceAll("\\\\", "/"));
                }

                // finally clean up the script
                cmd = ParamReplacementSvc.get().clearUnusedReplacements(cmd);

                Matcher m = scriptCmdPattern.matcher(cmd);
                while (m.find())
                {
                    String value = m.group().trim();
                    if (value.startsWith("'"))
                        value = m.group(1).trim();
                    else if (value.startsWith("\""))
                        value = m.group(2).trim();

                    params.add(value);
                }

                // append the script file, if it wasn't part of the command
                if (!specifiedScript)
                    params.add(scriptFilePath);
            }
            else
                params.add(scriptFilePath);

            return params.toArray(new String[params.size()]);
        }
        catch (Exception e)
        {
            throw new ScriptException(e);
        }
    }

    /**
     * Execute the external script engine in separate process
     * @return the exit code for the invocation - 0 if the process completed successfully.
     */
    protected int runProcess(ScriptContext context, ProcessBuilder pb, StringBuffer output)
    {
        Process proc;
        try
        {
            pb.redirectErrorStream(true);
            proc = pb.start();
        }
        catch (SecurityException se)
        {
            throw new RuntimeException(se);
        }
        catch (IOException eio)
        {
            Map<String, String> env = pb.environment();
            throw new RuntimeException("Failed starting process '" + pb.command() + "'. " +
                    "Must be on server path. (PATH=" + env.get("PATH") + ")", eio);
        }

        // Write script process output to the provided writer
        // if the writer isn't the original writer (a PrintWriter over the tomcat console).
        Writer writer = context.getWriter();
        if (writer == _originalWriter)
            writer = null;

        BufferedReader procReader = null;
        try
        {
            procReader = new BufferedReader(new InputStreamReader(proc.getInputStream()));
            String line;
            while ((line = procReader.readLine()) != null)
            {
                output.append(line);
                output.append('\n');
                if (writer != null)
                {
                    writer.write(line);
                    writer.write('\n');
                    // flush after every write so LogPrintWriter will forward the message to the Log4j Logger
                    writer.flush();
                }
            }
            if (writer != null)
                writer.flush();
        }
        catch (IOException eio)
        {
            throw new RuntimeException("Failed writing output for process in '" + pb.directory().getPath() + "'.", eio);
        }
        finally
        {
            if (procReader != null)
                try {procReader.close();} catch(IOException ignored) {}
        }

        try
        {
            int code = proc.waitFor();
            appendConsoleOutput(context, output);

            return code;
        }
        catch (InterruptedException ei)
        {
            throw new RuntimeException("Interrupted process for '" + pb.command() + " in " + pb.directory() + "'.", ei);
        }
    }

    protected File writeScriptFile(String script, ScriptContext context, List<String> extensions)
    {
        // write out the script file to disk using the first extension as the default
        File scriptFile;
        boolean isBinaryScript = false;

        Bindings bindings = context.getBindings(ScriptContext.ENGINE_SCOPE);

        if (bindings.containsKey(ExternalScriptEngine.SCRIPT_PATH))
        {
            File path = new File((String)bindings.get(ExternalScriptEngine.SCRIPT_PATH));
            isBinaryScript = isBinary(path);

            // if the script is a binary file, no parameter replacement can be performed on the script, so we
            // just execute it in place instead of moving to the temp folder
            if (isBinaryScript)
                scriptFile = path;
            else
                scriptFile = new File(getWorkingDir(context), path.getName());
        }
        else
            scriptFile = new File(getWorkingDir(context), "script." + extensions.get(0));

        bindings.put(REWRITTEN_SCRIPT_FILE, scriptFile);

        try {
            if (!isBinaryScript)
            {
                // process any replacements specified in the script context
                if (bindings.containsKey(PARAM_REPLACEMENT_MAP))
                {
                    for (Map.Entry<String, String> param : ((Map<String, String>)bindings.get(PARAM_REPLACEMENT_MAP)).entrySet())
                    {
                        script = ParamReplacementSvc.get().processInputReplacement(script, param.getKey(), param.getValue());
                    }
                }
                PrintWriter pw = new PrintWriter(new BufferedWriter(new FileWriter(scriptFile)));
                pw.write(script);
                pw.close();
            }
        }
        catch(Exception e)
        {
            ExceptionUtil.logExceptionToMothership(null, e);
        }

        return scriptFile;
    }

    protected void appendConsoleOutput(ScriptContext context, StringBuffer sb)
    {
        // Write script process output to the provided writer
        // if the writer isn't the original writer (a PrintWriter over the tomcat console).
        Writer writer = context.getWriter();
        if (writer == _originalWriter)
            writer = null;

        // if additional console output is written to a file, append it to the output string.
        BufferedReader br = null;
        try {
            String fileName = _def.getOutputFileName();
            if (fileName != null)
            {
                File file = getConsoleOutputFile(context);
                if (file != null)
                {
                    br = new BufferedReader(new FileReader(file));
                    String l;
                    while ((l = br.readLine()) != null)
                    {
                        sb.append(l);
                        sb.append('\n');
                        if (writer != null)
                        {
                            writer.append(l);
                            writer.append('\n');
                        }
                    }

                    if (writer != null)
                        writer.flush();
                }
            }
        }
        catch (IOException e)
        {
            throw new RuntimeException("Failed reading console output from external process", e);
        }
        finally
        {
            if (br != null)
                try {br.close();} catch(IOException ignored) {}
        }
    }

    /** Get the expected console out file or null if it doesn't exist. */
    @Nullable
    public File getConsoleOutputFile(ScriptContext context)
    {
        String fileName = _def.getOutputFileName();
        if (fileName != null)
        {
            if (context.getAttribute(REWRITTEN_SCRIPT_FILE) instanceof File)
            {
                File scriptFile = (File)context.getAttribute(REWRITTEN_SCRIPT_FILE);

                // Replace the ${scriptName} substitution with the actual name of the script file (minus extension)
                // E.g., if "script.R" is the filename and "${scriptName}.Rout" is the replacement, try "script.Rout"
                int index = scriptFile.getName().lastIndexOf(".");
                if (index != -1)
                {
                    String outFile = fileName.replace(SCRIPT_NAME_REPLACEMENT, scriptFile.getName().substring(0, index));
                    File file = new File(getWorkingDir(context), outFile);
                    if (file.exists())
                        return file;
                }

                // Replace the ${scriptName} substitution with the actual name of the script file (including extension)
                // E.g., if "script.r" is the filename and "${scriptName}.Rout" is the replacement, try "script.r.Rout"
                String outFile = fileName.replace(SCRIPT_NAME_REPLACEMENT, scriptFile.getName());
                File file = new File(getWorkingDir(context), outFile);
                if (file.exists())
                    return file;
            }

            File file = new File(getWorkingDir(context), fileName);
            if (file.exists())
                return file;
        }

        return null;
    }
}
