#nullable disable

public class Patient
{
    public string Name { get; private set; }
    public int Priority { get; private set; }

    public Patient(string name, int priority)
    {
        Name = name;
        Priority = priority;
    }

    public void SetPriority(int p)
    {
        Priority = p;
    }
}

public class Node
{
    public Patient Data;
    public Node Next;

    public Node(Patient data)
    {
        Data = data;
        Next = null;
    }
}

public class PriorQueue
{
    private Node head;

    public void Insert(Patient p)
    {
        Node newNode = new Node(p);

        if (head == null || p.Priority < head.Data.Priority)
        {
            newNode.Next = head;
            head = newNode;
            return;
        }

        Node cur = head;
        while (cur.Next != null && cur.Next.Data.Priority <= p.Priority)
        {
            cur = cur.Next;
        }

        newNode.Next = cur.Next;
        cur.Next = newNode;
    }

    public Patient Remove()
    {
        if (head == null) return null;
        Patient top = head.Data;
        head = head.Next;
        return top;
    }

    public bool UpdatePriority(string name, int newP)
    {
        Node prev = null;
        Node cur = head;

        while (cur != null && cur.Data.Name != name)
        {
            prev = cur;
            cur = cur.Next;
        }

        if (cur == null) return false;

        if (prev == null) head = cur.Next;
        else prev.Next = cur.Next;

        Insert(new Patient(name, newP));
        return true;
    }
}

class Program
{
    static void Main()
    {
        PriorQueue pq = new PriorQueue();
        pq.Insert(new Patient("John", 5));
        pq.Insert(new Patient("Alice", 2));
        pq.Insert(new Patient("Bob", 4));
        pq.UpdatePriority("Bob", 1);

        Patient p;
        while ((p = pq.Remove()) != null)
        {
            Console.WriteLine("Serving " + p.Name + " (priority " + p.Priority + ")");
        }
    }
}
