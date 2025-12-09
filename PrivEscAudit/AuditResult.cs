using System;

namespace PrivEscAudit
{
    public class AuditResult
    {
        public string Title { get; set; }
        public string Description { get; set; }
        public string Command { get; set; }
        public int ProbabilityScore { get; set; }

        public override string ToString()
        {
            return $"{Title}\n{Description}\nCommand:\n{Command}\nProbability: {ProbabilityScore}%\n--------------------------------------------------";
        }
    }
}
