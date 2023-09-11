namespace MIPConsoleTools
{
    #region Support classes
    internal class ManagedThreadIdGenerator
    {
        public override string ToString() => Environment.CurrentManagedThreadId.ToString();
    }
#endregion
}
