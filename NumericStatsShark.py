import pyshark
import sys, getopt,os

#Use: python3.9 NumericStatsShark.py -i [dump_name] -o [output_file_name] -t [threshold_value]
#dump_name is the wireshark dump file path.
#output_file_name is the name give to output files. Optional. Default: Output
#threshold_value is the threshold value to perform a temporal analysis on a call. Optional. Default: 10
#After closing mitmproxy a file couple "filename.csv" and "filename.mf.csv" will be generated.

def main(argv):
    os.chdir(os.path.dirname(__file__))
    inputfile = ''
    outputfile = ''
    threshold = 10 #valore di default
    try:
        opts, args = getopt.getopt(argv,"hi:o:t:",["ifile=","ofile="])
    except getopt.GetoptError:
        print(f"{sys.argv[0]} -i <inputfile> -o <outputfile> -t <threshold>")
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            print(f"{sys.argv[0]} -i <inputfile> -o <outputfile>")
            sys.exit()
        elif opt in ("-i", "--ifile"):
            inputfile = arg
        elif opt in ("-o", "--ofile"):
            outputfile = arg
        elif opt in ("-o", "--ofile"):
            threshold = arg
    result = loadFileStrings(inputfile)
    writeToFile(outputfile, result)
    writeMostFrequentCalls(outputfile, threshold, result)
    

def loadFileStrings(path):
    calls = []
    currentId = 1
    packets = pyshark.FileCapture(path, display_filter="http && http.request.method == \"CONNECT\"")
    try:
        for packet in packets:
            host = packet.http._all_fields["http.host"]    
            time = packet.sniff_time
            index = getCallIndex(calls, host)
            if index == None:
                calls.append(CallEntry(currentId,host, time))
                currentId = currentId + 1
            else:
                calls[index].increment(time)    
        return sorted(calls,key=lambda x: x.call)
    except AttributeError as e:
        pass

def writeToFile(filename, calls):
    with open(filename + ".csv", 'w') as f:
        f.write("Id;Richiesta;Numero Occorrenze\n")
        for item in calls:
            f.write("%s\n" % item.__str__())

def writeMostFrequentCalls(filename, threshold, calls):
    with open(filename+".mf.csv", 'w') as f:
        filtered_items = filter(lambda x: (x.number > threshold), calls)
        for item in filtered_items:
            f.write("%s\n\n" % item.frequency_mean__repr__())
            f.write("%s\n\n" % item.frequency_stats__repr__())
            f.write("%s\n" % item.frequency__repr__())

def getCallIndex(list, call):
    i = 0
    for x in list:
        if x.call == call:
            return i
        i = i + 1
    else:
        return None


class CallEntry:

    def __init__(self,callId,call,time):
        super().__init__()
        self.call = call
        self.number = 1
        self.id = callId
        self.times = []
        self.times.append(time)

    def increment(self, time):
        self.number = self.number + 1
        self.times.append(time)

    def timeFrequencyMean(self):
        mean = 0
        times = sorted(self.times)
        timesLen = len(times)
        for i in range(0,timesLen):
            if i != (timesLen - 1):
                timeDiff = times[i+1] - times[i]
                mean = mean + timeDiff.seconds 
        return int(mean / (timesLen - 1)) 

    def timeFrequencyStats(self):
        statsCounter = {"0-1 minuto":0, "1-5 minuti":0, "5-15 minuti":0,"15-30 minuti":0, "30-45 minuti":0, "45-60 minuti":0, "60+ minuti":0}
        times = sorted(self.times)
        timesLen = len(times)
        for i in range(0,timesLen):
            if i != (timesLen - 1):
                timeDiff = (times[i+1] - times[i]).seconds
                statsCounter[self.getTimeFrequencyStasKey(timeDiff)] = statsCounter[self.getTimeFrequencyStasKey(timeDiff)] + 1
        return statsCounter
 
    def getTimeFrequencyStasKey(self, seconds):
        if seconds <= 60:
            return "0-1 minuto"
        if seconds > 60 and seconds <= 300:
            return "1-5 minuti"
        if seconds > 300 and seconds <= 900:
            return "5-15 minuti"
        if seconds > 900 and seconds <= 1800:
            return "15-30 minuti"
        if seconds > 1800 and seconds <= 2700:
            return "30-45 minuti"
        if seconds > 2700 and seconds <= 3600:
            return "45-60 minuti"
        if seconds > 3600:
            return "60+ minuti"
    
    def __str__(self):
        return f"{self.id};{self.call};{self.number}"

    def __repr__(self):
        return self.__str__()

    def frequency__repr__(self):
        times = sorted(self.times)
        times_repr = "Id;Richiesta;Occorrenze\n"
        for time in times:
            times_repr = f"{times_repr}{self.id};{self.call};{time}\n"
        return times_repr

    def frequency_stats__repr__(self):
        stats = self.timeFrequencyStats()
        frequency_stats_repr = "Tempo trascorso;Numero chiamate\n"
        for key, value in stats.items():
            frequency_stats_repr = f"{frequency_stats_repr}{key};{value}\n"
        return frequency_stats_repr

    def frequency_mean__repr__(self):
        return f"Richiesta;Tempo medio tra chiamate\n{self.call};{self.timeFrequencyMean()}"

if __name__ == "__main__":
    main(sys.argv[1:])