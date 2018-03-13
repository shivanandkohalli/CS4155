import java.util.HashMap;
import java.util.Map;


public class TrieNode {
	private Map<Character,TrieNode> child;
	private boolean isMatch;
	
	public Map<Character, TrieNode> getChild() {
		return this.child;
	}

	public TrieNode addToChild(char s) {
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
		this.child = new HashMap<Character, TrieNode>();
		this.isMatch = false;
	}
}
