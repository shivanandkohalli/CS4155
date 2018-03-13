import java.util.HashMap;
import java.util.Map;


public class TrieNode {
	private Map<String,TrieNode> child;
	private boolean isMatch;
	
	public Map<String, TrieNode> getChild() {
		return this.child;
	}

	public TrieNode addToChild(String s) {
		TrieNode t = new TrieNode();
		this.child.put(s,t);
		return t;
	}

	public boolean isMatch() {
		return this.isMatch;
	}

	public void setMatch(boolean isMatch) {
		this.isMatch = isMatch;
	}

	public TrieNode()
	{
		this.child = new HashMap<String, TrieNode>();
		this.isMatch = false;
	}
}
